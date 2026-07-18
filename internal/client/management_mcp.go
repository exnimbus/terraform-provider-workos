// Copyright (c) ExNimbus
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const ManagementMCPEndpoint = "https://mcp.workos.com/mcp"

var ErrMCPNotLoggedIn = errors.New("WorkOS Management MCP login required")

// ManagementClient calls the official WorkOS Management MCP over streamable HTTP.
type ManagementClient struct {
	httpClient *oauthHTTPClient
}

// NewManagementClient loads MCP OAuth credentials from CI variables or the OS keychain.
func NewManagementClient(ctx context.Context) (*ManagementClient, error) {
	credentials, persist, err := loadMCPCredentials()
	if err != nil {
		return nil, err
	}
	httpClient, err := newOAuthHTTPClient(ctx, credentials, persist)
	if err != nil {
		return nil, err
	}
	return &ManagementClient{httpClient: httpClient}, nil
}

func (c *ManagementClient) call(ctx context.Context, tool string, arguments, target any) error {
	transport := &mcp.StreamableClientTransport{
		Endpoint:             ManagementMCPEndpoint,
		HTTPClient:           c.httpClient.Client,
		DisableStandaloneSSE: true,
	}
	mcpClient := mcp.NewClient(&mcp.Implementation{Name: "terraform-provider-workos", Version: "v2.5.0"}, nil)
	session, err := mcpClient.Connect(ctx, transport, nil)
	if err != nil {
		return fmt.Errorf("connect to WorkOS Management MCP: %w", redactError(err))
	}
	defer session.Close()

	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: arguments})
	if err != nil {
		return fmt.Errorf("call WorkOS Management MCP %s tool: %w", tool, redactError(err))
	}
	payload, err := toolResultJSON(result)
	if err != nil {
		return err
	}
	if target != nil && len(payload) != 0 {
		if err := json.Unmarshal(payload, target); err != nil {
			return fmt.Errorf("decode WorkOS Management MCP response: %w", err)
		}
	}
	return nil
}

func toolResultJSON(result *mcp.CallToolResult) ([]byte, error) {
	var payload []byte
	if result.StructuredContent != nil {
		var err error
		payload, err = json.Marshal(result.StructuredContent)
		if err != nil {
			return nil, fmt.Errorf("encode WorkOS Management MCP response: %w", err)
		}
	} else {
		var text strings.Builder
		for _, content := range result.Content {
			if value, ok := content.(*mcp.TextContent); ok {
				text.WriteString(value.Text)
			}
		}
		payload = []byte(text.String())
	}
	if result.IsError {
		return nil, fmt.Errorf("WorkOS Management MCP operation failed: %s", redact(string(payload)))
	}
	return payload, nil
}

func (c *ManagementClient) Query(ctx context.Context, operation, environmentID string, variables map[string]any, target any) error {
	arguments := map[string]any{"operation": operation}
	if environmentID != "" {
		arguments["environment_id"] = environmentID
	}
	if len(variables) != 0 {
		arguments["variables"] = variables
	}
	return c.call(ctx, "query", arguments, target)
}

func (c *ManagementClient) Mutate(ctx context.Context, operation, environmentID string, variables map[string]any) error {
	arguments := map[string]any{"operation": operation, "variables": variables}
	if environmentID != "" {
		arguments["environment_id"] = environmentID
	}
	return c.call(ctx, "mutate", arguments, nil)
}

type AuthKitApplication struct {
	ID                string         `json:"id"`
	Name              string         `json:"name"`
	ClientID          string         `json:"clientId"`
	EnvironmentID     string         `json:"environmentId"`
	InitiateLoginURI  *string        `json:"initiateLoginUri"`
	AppHomepageURL    *string        `json:"appHomepageUrl"`
	MaxSessionTime    int64          `json:"maxSessionTime"`
	AccessTokenExpiry int64          `json:"accessTokenExpiry"`
	InactivityTimeout int64          `json:"inactivityTimeout"`
	RedirectURIs      AuthKitURIList `json:"redirectUris"`
	LogoutURIs        AuthKitURIList `json:"logoutUris"`
	WebOrigins        AuthKitURIList `json:"webOrigins"`
}

type AuthKitURI struct {
	ID        string `json:"id"`
	URI       string `json:"uri"`
	Origin    string `json:"origin"`
	Default   bool   `json:"default"`
	IsDefault bool   `json:"isDefault"`
}

type AuthKitURIList []AuthKitURI

func (values *AuthKitURIList) UnmarshalJSON(data []byte) error {
	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for _, item := range raw {
		var value AuthKitURI
		if err := json.Unmarshal(item, &value); err == nil {
			if value.URI != "" || value.Origin != "" || value.ID != "" {
				*values = append(*values, value)
				continue
			}
		}
		var text string
		if err := json.Unmarshal(item, &text); err != nil {
			return err
		}
		*values = append(*values, AuthKitURI{URI: text, Origin: text})
	}
	return nil
}

type AuthKitSettings struct {
	AllowSignUp                     bool   `json:"allowSignUp"`
	IsWaitlistEnabled               bool   `json:"isWaitlistEnabled"`
	IsAuthKitEnabled                bool   `json:"isAuthkitEnabled"`
	IsAuthKitIDPInitiatedSSOEnabled bool   `json:"isAuthkitIdpInitiatedSsoEnabled"`
	IsEmailVerificationRequired     bool   `json:"isEmailVerificationRequired"`
	IsAppleOAuthEnabled             bool   `json:"isAppleOauthEnabled"`
	IsBitbucketOAuthEnabled         bool   `json:"isBitbucketOauthEnabled"`
	IsDiscordOAuthEnabled           bool   `json:"isDiscordOauthEnabled"`
	IsGitHubOAuthEnabled            bool   `json:"isGithubOauthEnabled"`
	IsGitLabOAuthEnabled            bool   `json:"isGitLabOauthEnabled"`
	IsGoogleOAuthEnabled            bool   `json:"isGoogleOauthEnabled"`
	IsIntuitOAuthEnabled            bool   `json:"isIntuitOauthEnabled"`
	IsLinkedInOAuthEnabled          bool   `json:"isLinkedInOauthEnabled"`
	IsMicrosoftOAuthEnabled         bool   `json:"isMicrosoftOauthEnabled"`
	IsSalesforceOAuthEnabled        bool   `json:"isSalesforceOauthEnabled"`
	IsSlackOAuthEnabled             bool   `json:"isSlackOauthEnabled"`
	IsVercelMarketplaceOAuthEnabled bool   `json:"isVercelMarketplaceOauthEnabled"`
	IsVercelOAuthEnabled            bool   `json:"isVercelOauthEnabled"`
	IsXeroOAuthEnabled              bool   `json:"isXeroOauthEnabled"`
	IsMagicAuthEnabled              bool   `json:"isMagicAuthEnabled"`
	IsPasswordAuthEnabled           bool   `json:"isPasswordAuthEnabled"`
	IsPasswordLowercaseRequired     bool   `json:"isPasswordLowercaseRequired"`
	IsPasswordNumberRequired        bool   `json:"isPasswordNumberRequired"`
	IsPasswordPwnedRequired         bool   `json:"isPasswordPwnedRequired"`
	IsPasswordSymbolRequired        bool   `json:"isPasswordSymbolRequired"`
	IsPasswordUppercaseRequired     bool   `json:"isPasswordUppercaseRequired"`
	IsPasskeyAuthEnabled            bool   `json:"isPasskeyAuthEnabled"`
	IsPasskeyProgressiveEnrollment  bool   `json:"isPasskeyProgressiveEnrollmentEnabled"`
	IsSSOEnabled                    bool   `json:"isSsoEnabled"`
	MFAEnabled                      string `json:"mfaEnabled"`
	PasswordMinimumLength           int64  `json:"passwordMinimumLength"`
}

func (c *ManagementClient) DefaultAuthKitApplication(ctx context.Context, environmentID string) (*AuthKitApplication, error) {
	var response struct {
		Application AuthKitApplication `json:"defaultUserlandApplication"`
	}
	if err := c.Query(ctx, "defaultAuthkitApplication", environmentID, nil, &response); err != nil {
		return nil, err
	}
	return &response.Application, nil
}

func (c *ManagementClient) AuthKitSettings(ctx context.Context, environmentID string) (*AuthKitSettings, error) {
	var response struct {
		Environment struct {
			Settings AuthKitSettings `json:"userlandSettings"`
		} `json:"environment"`
	}
	if err := c.Query(ctx, "authkitSettings", environmentID, nil, &response); err != nil {
		return nil, err
	}
	return &response.Environment.Settings, nil
}
