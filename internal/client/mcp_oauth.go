// Copyright (c) ExNimbus
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/zalando/go-keyring"
	"golang.org/x/oauth2"
)

const (
	mcpKeychainService = "exnimbus.terraform-provider-workos.mcp"
	mcpClientIDAccount = "client_id"
	mcpRefreshAccount  = "refresh_token"
	mcpAccessAccount   = "access_token"
	mcpIssuer          = "https://signin.workos.com"
	mcpDeviceGrant     = "urn:ietf:params:oauth:grant-type:device_code"
)

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(bearer\s+)[^\s,;]+`),
	regexp.MustCompile(`(?i)((?:access_token|refresh_token|client_secret)["'=:\s]+)[^"'\s,}]+`),
	regexp.MustCompile(`\b(?:sk|pk|whsec)_[A-Za-z0-9_-]+\b`),
}

type mcpCredentials struct {
	ClientID     string
	AccessToken  string
	RefreshToken string
}

type oauthHTTPClient struct {
	*http.Client
}

func loadMCPCredentials() (mcpCredentials, bool, error) {
	clientID, refreshToken := os.Getenv("WORKOS_MCP_CLIENT_ID"), os.Getenv("WORKOS_MCP_REFRESH_TOKEN")
	if clientID != "" || refreshToken != "" {
		if clientID == "" || refreshToken == "" {
			return mcpCredentials{}, false, errors.New("WORKOS_MCP_CLIENT_ID and WORKOS_MCP_REFRESH_TOKEN must be set together")
		}
		return mcpCredentials{ClientID: clientID, RefreshToken: refreshToken}, false, nil
	}

	clientID, clientErr := keyring.Get(mcpKeychainService, mcpClientIDAccount)
	accessToken, _ := keyring.Get(mcpKeychainService, mcpAccessAccount)
	refreshToken, refreshErr := keyring.Get(mcpKeychainService, mcpRefreshAccount)
	if errors.Is(clientErr, keyring.ErrNotFound) && errors.Is(refreshErr, keyring.ErrNotFound) && accessToken == "" {
		return mcpCredentials{}, false, ErrMCPNotLoggedIn
	}
	if clientErr != nil || (refreshErr != nil && accessToken == "") {
		return mcpCredentials{}, false, fmt.Errorf("read WorkOS MCP credentials from OS keychain: %w", errors.Join(clientErr, refreshErr))
	}
	return mcpCredentials{ClientID: clientID, AccessToken: accessToken, RefreshToken: refreshToken}, true, nil
}

func newOAuthHTTPClient(ctx context.Context, credentials mcpCredentials, persist bool) (*oauthHTTPClient, error) {
	if credentials.ClientID == "" || (credentials.RefreshToken == "" && credentials.AccessToken == "") {
		return nil, ErrMCPNotLoggedIn
	}
	if credentials.AccessToken != "" {
		httpClient := oauth2.NewClient(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: credentials.AccessToken, TokenType: "Bearer"}))
		httpClient.Timeout = DefaultTimeout
		return &oauthHTTPClient{Client: httpClient}, nil
	}
	config := &oauth2.Config{
		ClientID: credentials.ClientID,
		Endpoint: oauth2.Endpoint{TokenURL: mcpIssuer + "/oauth2/token?resource=" + url.QueryEscape(ManagementMCPEndpoint), AuthStyle: oauth2.AuthStyleInParams},
		Scopes:   []string{"openid", "profile", "email", "offline_access"},
	}
	source := config.TokenSource(ctx, &oauth2.Token{RefreshToken: credentials.RefreshToken})
	if persist {
		source = &persistingTokenSource{source: source, previousRefreshToken: credentials.RefreshToken}
	}
	httpClient := oauth2.NewClient(ctx, source)
	httpClient.Timeout = DefaultTimeout
	return &oauthHTTPClient{Client: httpClient}, nil
}

type persistingTokenSource struct {
	source               oauth2.TokenSource
	previousRefreshToken string
	mu                   sync.Mutex
}

func (s *persistingTokenSource) Token() (*oauth2.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	previousRefreshToken := s.previousRefreshToken
	token, err := s.source.Token()
	if err != nil {
		return nil, errors.New(redactKnown(err.Error(), previousRefreshToken))
	}
	if token.RefreshToken == "" {
		token.RefreshToken = previousRefreshToken
	}
	if token.RefreshToken != previousRefreshToken {
		if err := keyring.Set(mcpKeychainService, mcpRefreshAccount, token.RefreshToken); err != nil {
			return nil, fmt.Errorf("store refreshed WorkOS MCP credential in OS keychain: %w", err)
		}
		s.previousRefreshToken = token.RefreshToken
	}
	return token, nil
}

type oauthEndpoints struct {
	Register  string
	Device    string
	Token     string
	Authorize string
}

var workOSEndpoints = oauthEndpoints{
	Register:  mcpIssuer + "/oauth2/register",
	Device:    mcpIssuer + "/oauth2/device_authorization",
	Token:     mcpIssuer + "/oauth2/token",
	Authorize: mcpIssuer + "/oauth2/authorize",
}

// MCPLogin performs AuthKit's OAuth authorization-code flow and stores only refresh credentials.
func MCPLogin(ctx context.Context, out io.Writer) error {
	credentials, err := authCodeLogin(ctx, out, workOSEndpoints)
	if err != nil {
		return redactError(err)
	}
	if err := keyring.Set(mcpKeychainService, mcpClientIDAccount, credentials.ClientID); err != nil {
		return fmt.Errorf("store WorkOS MCP client ID in OS keychain: %w", err)
	}
	if err := keyring.Set(mcpKeychainService, mcpAccessAccount, credentials.AccessToken); err != nil {
		return fmt.Errorf("store WorkOS MCP access credential in OS keychain: %w", err)
	}
	if err := keyring.Set(mcpKeychainService, mcpRefreshAccount, credentials.RefreshToken); err != nil {
		_ = keyring.Delete(mcpKeychainService, mcpClientIDAccount)
		return fmt.Errorf("store WorkOS MCP refresh credential in OS keychain: %w", err)
	}
	fmt.Fprintln(out, "WorkOS Management MCP login saved in the OS keychain.")
	return nil
}

func authCodeLogin(ctx context.Context, out io.Writer, endpoints oauthEndpoints) (mcpCredentials, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return mcpCredentials{}, fmt.Errorf("listen for WorkOS OAuth callback: %w", err)
	}
	defer listener.Close()
	redirectURI := "http://" + listener.Addr().String() + "/callback"
	clientID := os.Getenv("WORKOS_MCP_CLIENT_ID")
	if clientID == "" {
		clientID, err = registerClient(ctx, endpoints.Register, redirectURI)
		if err != nil {
			return mcpCredentials{}, err
		}
	}
	verifier := oauth2.GenerateVerifier()
	config := &oauth2.Config{ClientID: clientID, Endpoint: oauth2.Endpoint{AuthURL: endpoints.Authorize, TokenURL: endpoints.Token, AuthStyle: oauth2.AuthStyleInParams}, RedirectURL: redirectURI, Scopes: []string{"openid", "profile", "email", "offline_access"}}
	state := verifier
	result := make(chan struct{ code, state, failure string }, 1)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/callback" {
			http.NotFound(w, r)
			return
		}
		result <- struct{ code, state, failure string }{code: r.URL.Query().Get("code"), state: r.URL.Query().Get("state"), failure: r.URL.Query().Get("error")}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "Authorization complete. You can return to the terminal.")
	})}
	go func() { _ = server.Serve(listener) }()
	defer func() { _ = server.Shutdown(context.Background()) }()
	authURL := config.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("resource", ManagementMCPEndpoint))
	fmt.Fprintf(out, "Open %s to authorize the WorkOS Management MCP provider.\n", authURL)
	_ = openBrowser(authURL)
	select {
	case <-ctx.Done():
		return mcpCredentials{}, ctx.Err()
	case callback := <-result:
		if callback.failure != "" {
			return mcpCredentials{}, fmt.Errorf("WorkOS OAuth authorization failed: %s", callback.failure)
		}
		if callback.state != state || callback.code == "" {
			return mcpCredentials{}, errors.New("WorkOS OAuth callback state validation failed")
		}
		token, err := config.Exchange(ctx, callback.code, oauth2.VerifierOption(verifier))
		if err != nil {
			return mcpCredentials{}, fmt.Errorf("exchange WorkOS OAuth authorization code: %w", err)
		}
		if token.RefreshToken == "" {
			return mcpCredentials{}, errors.New("WorkOS OAuth response did not include a refresh token")
		}
		return mcpCredentials{ClientID: clientID, AccessToken: token.AccessToken, RefreshToken: token.RefreshToken}, nil
	}
}

func registerClient(ctx context.Context, endpoint, redirectURI string) (string, error) {
	body := strings.NewReader(fmt.Sprintf(`{"client_name":"OpenTofu WorkOS Provider","application_type":"native","redirect_uris":[%q],"grant_types":["authorization_code","refresh_token"],"token_endpoint_auth_method":"none"}`, redirectURI))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var result struct {
		ClientID string `json:"client_id"`
	}
	if err := decodeOAuthResponse(resp, &result); err != nil {
		return "", fmt.Errorf("register WorkOS MCP client: %w", err)
	}
	if result.ClientID == "" {
		return "", errors.New("register WorkOS MCP client: missing client_id")
	}
	return result.ClientID, nil
}

func deviceLogin(ctx context.Context, out io.Writer, endpoints oauthEndpoints) (mcpCredentials, error) {
	clientID := os.Getenv("WORKOS_MCP_CLIENT_ID")
	if clientID == "" {
		var err error
		clientID, err = registerDeviceClient(ctx, endpoints.Register)
		if err != nil {
			return mcpCredentials{}, err
		}
	}
	form := url.Values{
		"client_id": {clientID},
		"scope":     {"openid profile email offline_access"},
	}
	var authorization struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int    `json:"expires_in"`
		Interval                int    `json:"interval"`
	}
	if err := postFormJSON(ctx, endpoints.Device, form, &authorization); err != nil {
		return mcpCredentials{}, fmt.Errorf("start WorkOS MCP device authorization: %w", err)
	}
	fmt.Fprintf(out, "Open %s and enter code %s\n", authorization.VerificationURI, authorization.UserCode)
	if authorization.VerificationURIComplete != "" {
		_ = openBrowser(authorization.VerificationURIComplete)
	}

	interval := time.Duration(authorization.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	deadline := time.NewTimer(time.Duration(authorization.ExpiresIn) * time.Second)
	defer deadline.Stop()
	for {
		select {
		case <-ctx.Done():
			return mcpCredentials{}, ctx.Err()
		case <-deadline.C:
			return mcpCredentials{}, errors.New("WorkOS MCP device authorization expired")
		case <-time.After(interval):
		}
		form = url.Values{
			"client_id":   {clientID},
			"device_code": {authorization.DeviceCode},
			"grant_type":  {mcpDeviceGrant},
		}
		var token struct {
			RefreshToken string `json:"refresh_token"`
			Error        string `json:"error"`
		}
		status, err := postFormJSONStatus(ctx, endpoints.Token, form, &token)
		if err == nil && status < http.StatusBadRequest && token.RefreshToken != "" {
			return mcpCredentials{ClientID: clientID, RefreshToken: token.RefreshToken}, nil
		}
		switch token.Error {
		case "authorization_pending":
			continue
		case "slow_down":
			interval += 5 * time.Second
			continue
		default:
			if err != nil {
				return mcpCredentials{}, fmt.Errorf("complete WorkOS MCP device authorization: %w", err)
			}
			return mcpCredentials{}, fmt.Errorf("complete WorkOS MCP device authorization: OAuth error %q", token.Error)
		}
	}
}

func registerDeviceClient(ctx context.Context, endpoint string) (string, error) {
	body := strings.NewReader(`{"client_name":"OpenTofu WorkOS Provider","application_type":"native","redirect_uris":["http://127.0.0.1"],"grant_types":["authorization_code","refresh_token"],"token_endpoint_auth_method":"none"}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var result struct {
		ClientID string `json:"client_id"`
	}
	if err := decodeOAuthResponse(resp, &result); err != nil {
		return "", fmt.Errorf("register WorkOS MCP device client: %w", err)
	}
	if result.ClientID == "" {
		return "", errors.New("register WorkOS MCP device client: missing client_id")
	}
	return result.ClientID, nil
}

func postFormJSON(ctx context.Context, endpoint string, form url.Values, target any) error {
	status, err := postFormJSONStatus(ctx, endpoint, form, target)
	if err == nil && status >= http.StatusBadRequest {
		return fmt.Errorf("OAuth endpoint returned HTTP %d", status)
	}
	return err
}

func postFormJSONStatus(ctx context.Context, endpoint string, form url.Values, target any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, decodeOAuthResponse(resp, target)
}

func decodeOAuthResponse(resp *http.Response, target any) error {
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, target); err != nil {
		return fmt.Errorf("decode OAuth response (HTTP %d)", resp.StatusCode)
	}
	return nil
}

func MCPStatus(ctx context.Context, out io.Writer) error {
	credentials, persist, err := loadMCPCredentials()
	if err != nil {
		return err
	}
	client, err := newOAuthHTTPClient(ctx, credentials, persist)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, ManagementMCPEndpoint, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return redactError(err)
	}
	response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return errors.New("WorkOS Management MCP login is invalid; run login again")
	}
	fmt.Fprintf(out, "WorkOS Management MCP credentials are valid for client %s.\n", credentials.ClientID)
	return nil
}

func MCPLogout(out io.Writer) error {
	for _, account := range []string{mcpClientIDAccount, mcpAccessAccount, mcpRefreshAccount} {
		if err := keyring.Delete(mcpKeychainService, account); err != nil && !errors.Is(err, keyring.ErrNotFound) {
			return fmt.Errorf("delete WorkOS MCP credential from OS keychain: %w", err)
		}
	}
	fmt.Fprintln(out, "WorkOS Management MCP credentials removed from the OS keychain.")
	return nil
}

func openBrowser(target string) error {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		command = exec.Command("open", target)
	case "windows":
		command = exec.Command("rundll32", "url.dll,FileProtocolHandler", target)
	default:
		command = exec.Command("xdg-open", target)
	}
	return command.Start()
}

func redactError(err error) error {
	if err == nil {
		return nil
	}
	return errors.New(redact(err.Error()))
}

func redact(value string) string {
	for _, secret := range []string{os.Getenv("WORKOS_API_KEY"), os.Getenv("WORKOS_MCP_REFRESH_TOKEN")} {
		value = redactKnown(value, secret)
	}
	for _, pattern := range secretPatterns {
		value = pattern.ReplaceAllString(value, "${1}[REDACTED]")
	}
	return value
}

func redactKnown(value, secret string) string {
	if secret == "" {
		return value
	}
	return strings.ReplaceAll(value, secret, "[REDACTED]")
}
