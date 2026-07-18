// Copyright (c) ExNimbus
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	refreshToken, refreshErr := keyring.Get(mcpKeychainService, mcpRefreshAccount)
	if errors.Is(clientErr, keyring.ErrNotFound) && errors.Is(refreshErr, keyring.ErrNotFound) {
		return mcpCredentials{}, false, ErrMCPNotLoggedIn
	}
	if clientErr != nil || refreshErr != nil {
		return mcpCredentials{}, false, fmt.Errorf("read WorkOS MCP credentials from OS keychain: %w", errors.Join(clientErr, refreshErr))
	}
	return mcpCredentials{ClientID: clientID, RefreshToken: refreshToken}, true, nil
}

func newOAuthHTTPClient(ctx context.Context, credentials mcpCredentials, persist bool) (*oauthHTTPClient, error) {
	if credentials.ClientID == "" || credentials.RefreshToken == "" {
		return nil, ErrMCPNotLoggedIn
	}
	config := &oauth2.Config{
		ClientID: credentials.ClientID,
		Endpoint: oauth2.Endpoint{TokenURL: mcpIssuer + "/oauth2/token", AuthStyle: oauth2.AuthStyleInParams},
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
	previousRefreshToken := s.previousRefreshToken
	s.mu.Unlock()
	token, err := s.source.Token()
	if err != nil {
		return nil, errors.New(redactKnown(err.Error(), previousRefreshToken))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if token.RefreshToken != "" && token.RefreshToken != s.previousRefreshToken {
		if err := keyring.Set(mcpKeychainService, mcpRefreshAccount, token.RefreshToken); err != nil {
			return nil, fmt.Errorf("store refreshed WorkOS MCP credential in OS keychain: %w", err)
		}
		s.previousRefreshToken = token.RefreshToken
	}
	return token, nil
}

type oauthEndpoints struct {
	Register string
	Device   string
	Token    string
}

var workOSEndpoints = oauthEndpoints{
	Register: mcpIssuer + "/oauth2/register",
	Device:   mcpIssuer + "/oauth2/device_authorization",
	Token:    mcpIssuer + "/oauth2/token",
}

// MCPLogin performs WorkOS's OAuth device flow and stores only refresh credentials.
func MCPLogin(ctx context.Context, out io.Writer) error {
	credentials, err := deviceLogin(ctx, out, workOSEndpoints)
	if err != nil {
		return redactError(err)
	}
	if err := keyring.Set(mcpKeychainService, mcpClientIDAccount, credentials.ClientID); err != nil {
		return fmt.Errorf("store WorkOS MCP client ID in OS keychain: %w", err)
	}
	if err := keyring.Set(mcpKeychainService, mcpRefreshAccount, credentials.RefreshToken); err != nil {
		_ = keyring.Delete(mcpKeychainService, mcpClientIDAccount)
		return fmt.Errorf("store WorkOS MCP refresh credential in OS keychain: %w", err)
	}
	fmt.Fprintln(out, "WorkOS Management MCP login saved in the OS keychain.")
	return nil
}

func deviceLogin(ctx context.Context, out io.Writer, endpoints oauthEndpoints) (mcpCredentials, error) {
	clientID, err := registerDeviceClient(ctx, endpoints.Register)
	if err != nil {
		return mcpCredentials{}, err
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
	body := strings.NewReader(`{"client_name":"OpenTofu WorkOS Provider","application_type":"native","grant_types":["urn:ietf:params:oauth:grant-type:device_code","refresh_token"],"token_endpoint_auth_method":"none"}`)
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
	for _, account := range []string{mcpClientIDAccount, mcpRefreshAccount} {
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
