// Copyright (c) ExNimbus
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"reflect"
	"testing"

	"github.com/exnimbus/terraform-provider-workos/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
)

func TestAuthKitConfigurationSchemaAndURIInputs(t *testing.T) {
	response := &resource.SchemaResponse{}
	NewAuthKitConfigurationResource().Schema(context.Background(), resource.SchemaRequest{}, response)
	if response.Diagnostics.HasError() {
		t.Fatalf("unexpected schema diagnostics: %v", response.Diagnostics)
	}
	verification, ok := response.Schema.Attributes["email_verification_enabled"].(schema.BoolAttribute)
	if !ok || !verification.Computed {
		t.Fatal("email_verification_enabled must be computed")
	}
	protection, ok := response.Schema.Attributes["deletion_protection"].(schema.BoolAttribute)
	if !ok || !protection.Optional || protection.Default == nil {
		t.Fatal("deletion_protection must default on")
	}

	inputs := uriInputs([]string{"https://b.example/callback", "https://a.example/callback"}, []client.AuthKitURI{{ID: "uri_b", URI: "https://b.example/callback", Default: true}})
	want := []map[string]any{
		{"uri": "https://a.example/callback", "isDefault": false},
		{"uri": "https://b.example/callback", "isDefault": true, "id": "uri_b"},
	}
	if !reflect.DeepEqual(inputs, want) {
		t.Fatalf("uriInputs() = %#v, want %#v", inputs, want)
	}
}

func TestPasswordOnlyRejectsOtherAuthentication(t *testing.T) {
	settings := &client.AuthKitSettings{IsAuthKitEnabled: true, IsPasswordAuthEnabled: true}
	if !passwordOnly(settings) {
		t.Fatal("password-only settings were not recognized")
	}
	settings.IsGoogleOAuthEnabled = true
	if passwordOnly(settings) {
		t.Fatal("social OAuth drift was not detected")
	}
}
