// Copyright (c) ExNimbus
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/zalando/go-keyring"
)

func TestToolResultJSONAndRedaction(t *testing.T) {
	payload, err := toolResultJSON(&mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: `{"ok":true}`}}})
	if err != nil || string(payload) != `{"ok":true}` {
		t.Fatalf("unexpected tool result: %q, %v", payload, err)
	}

	t.Setenv("WORKOS_MCP_REFRESH_TOKEN", "refresh-secret-value")
	redacted := redact(`Bearer access-secret refresh_token="refresh-secret-value" sk_test_secret`)
	for _, secret := range []string{"access-secret", "refresh-secret-value", "sk_test_secret"} {
		if strings.Contains(redacted, secret) {
			t.Fatalf("secret %q was not redacted from %q", secret, redacted)
		}
	}
}

func TestDeviceLogin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/register":
			fmt.Fprint(response, `{"client_id":"client_device"}`)
		case "/device":
			if request.FormValue("client_id") != "client_device" {
				t.Fatalf("unexpected device client: %q", request.FormValue("client_id"))
			}
			fmt.Fprint(response, `{"device_code":"device_code","user_code":"ABCD","verification_uri":"https://example.test/device","expires_in":10,"interval":1}`)
		case "/token":
			if request.FormValue("grant_type") != mcpDeviceGrant || request.FormValue("device_code") != "device_code" {
				t.Fatalf("unexpected token form: %v", request.Form)
			}
			fmt.Fprint(response, `{"refresh_token":"refresh_device"}`)
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	var output strings.Builder
	credentials, err := deviceLogin(context.Background(), &output, oauthEndpoints{
		Register: server.URL + "/register",
		Device:   server.URL + "/device",
		Token:    server.URL + "/token",
	})
	if err != nil || credentials.ClientID != "client_device" || credentials.RefreshToken != "refresh_device" {
		t.Fatalf("unexpected login result: %#v, %v", credentials, err)
	}
	if !strings.Contains(output.String(), "ABCD") {
		t.Fatalf("device code was not shown: %q", output.String())
	}
}

func TestLoadMCPCredentials(t *testing.T) {
	keyring.MockInit()
	t.Setenv("WORKOS_MCP_CLIENT_ID", "")
	t.Setenv("WORKOS_MCP_REFRESH_TOKEN", "")
	if _, _, err := loadMCPCredentials(); !errors.Is(err, ErrMCPNotLoggedIn) {
		t.Fatalf("expected login error, got %v", err)
	}
	if err := keyring.Set(mcpKeychainService, mcpClientIDAccount, "client_test"); err != nil {
		t.Fatal(err)
	}
	if err := keyring.Set(mcpKeychainService, mcpRefreshAccount, "refresh_test"); err != nil {
		t.Fatal(err)
	}
	credentials, persist, err := loadMCPCredentials()
	if err != nil || !persist || credentials.ClientID != "client_test" || credentials.RefreshToken != "refresh_test" {
		t.Fatalf("unexpected credentials: %#v, persist=%v, err=%v", credentials, persist, err)
	}

	os.Setenv("WORKOS_MCP_CLIENT_ID", "client_ci")
	t.Cleanup(func() { _ = os.Unsetenv("WORKOS_MCP_CLIENT_ID") })
	if _, _, err := loadMCPCredentials(); err == nil {
		t.Fatal("expected partial CI credential error")
	}
}
