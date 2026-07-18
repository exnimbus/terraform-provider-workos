// Copyright (c) ExNimbus
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"os"
	"sort"

	"github.com/exnimbus/terraform-provider-workos/internal/client"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &AuthKitConfigurationResource{}
	_ resource.ResourceWithModifyPlan  = &AuthKitConfigurationResource{}
	_ resource.ResourceWithImportState = &AuthKitConfigurationResource{}
)

func NewAuthKitConfigurationResource() resource.Resource { return &AuthKitConfigurationResource{} }

type AuthKitConfigurationResource struct {
	management *client.ManagementClient
}

type AuthKitConfigurationResourceModel struct {
	ID                         types.String `tfsdk:"id"`
	EnvironmentID              types.String `tfsdk:"environment_id"`
	ApplicationID              types.String `tfsdk:"application_id"`
	ClientID                   types.String `tfsdk:"client_id"`
	ApplicationName            types.String `tfsdk:"application_name"`
	HomepageURL                types.String `tfsdk:"homepage_url"`
	InitiateLoginURI           types.String `tfsdk:"initiate_login_uri"`
	RedirectURIs               types.Set    `tfsdk:"redirect_uris"`
	LogoutURIs                 types.Set    `tfsdk:"logout_uris"`
	WebOrigins                 types.Set    `tfsdk:"web_origins"`
	AuthenticationMethod       types.String `tfsdk:"authentication_method"`
	AllowSignup                types.Bool   `tfsdk:"allow_signup"`
	MFA                        types.String `tfsdk:"mfa"`
	PasswordMinimumLength      types.Int64  `tfsdk:"password_minimum_length"`
	BreachedPasswordProtection types.Bool   `tfsdk:"breached_password_protection"`
	PasswordCompositionRules   types.Bool   `tfsdk:"password_composition_rules"`
	AccessTokenExpiry          types.Int64  `tfsdk:"access_token_expiry"`
	InactivityTimeout          types.Int64  `tfsdk:"inactivity_timeout"`
	MaximumSession             types.Int64  `tfsdk:"maximum_session"`
	EmailVerificationEnabled   types.Bool   `tfsdk:"email_verification_enabled"`
	DeletionProtection         types.Bool   `tfsdk:"deletion_protection"`
}

func (r *AuthKitConfigurationResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_authkit_configuration"
}

func (r *AuthKitConfigurationResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages the complete default AuthKit application and authentication policy for one WorkOS environment through the official Management MCP.",
		Attributes: map[string]schema.Attribute{
			"id":                 schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"environment_id":     schema.StringAttribute{Required: true},
			"application_id":     schema.StringAttribute{Computed: true},
			"client_id":          schema.StringAttribute{Computed: true},
			"application_name":   schema.StringAttribute{Required: true},
			"homepage_url":       schema.StringAttribute{Required: true},
			"initiate_login_uri": schema.StringAttribute{Required: true},
			"redirect_uris":      schema.SetAttribute{Required: true, ElementType: types.StringType},
			"logout_uris":        schema.SetAttribute{Required: true, ElementType: types.StringType},
			"web_origins":        schema.SetAttribute{Required: true, ElementType: types.StringType},
			"authentication_method": schema.StringAttribute{
				Required:   true,
				Validators: []validator.String{stringvalidator.OneOf("password")},
			},
			"allow_signup": schema.BoolAttribute{Required: true},
			"mfa": schema.StringAttribute{
				Required:   true,
				Validators: []validator.String{stringvalidator.OneOf("Off", "Optional", "Required")},
			},
			"password_minimum_length":      schema.Int64Attribute{Required: true},
			"breached_password_protection": schema.BoolAttribute{Required: true},
			"password_composition_rules":   schema.BoolAttribute{Required: true},
			"access_token_expiry":          schema.Int64Attribute{Required: true},
			"inactivity_timeout":           schema.Int64Attribute{Required: true},
			"maximum_session":              schema.Int64Attribute{Required: true},
			"email_verification_enabled":   schema.BoolAttribute{Computed: true},
			"deletion_protection":          schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true)},
		},
	}
}

func (r *AuthKitConfigurationResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	providerClient, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Resource Configure Type", fmt.Sprintf("Expected *client.Client, got %T.", req.ProviderData))
		return
	}
	management, err := providerClient.Management()
	if err != nil {
		resp.Diagnostics.AddError("WorkOS Management MCP Login Required", "Run `terraform-provider-workos login` or set WORKOS_MCP_CLIENT_ID and WORKOS_MCP_REFRESH_TOKEN together.")
		return
	}
	r.management = management
}

func (r *AuthKitConfigurationResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() || r.management == nil {
		return
	}
	var plan AuthKitConfigurationResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() || authKitPlanUnknown(plan) {
		return
	}
	application, err := r.management.DefaultAuthKitApplication(ctx, plan.EnvironmentID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to Validate AuthKit URLs", err.Error())
		return
	}
	redirects, logouts, origins, diagnostics := authKitURLValues(ctx, plan)
	resp.Diagnostics.Append(diagnostics...)
	if resp.Diagnostics.HasError() {
		return
	}
	for _, validation := range []struct {
		operation string
		variables map[string]any
	}{
		{"setAuthkitApplicationRedirectUris", map[string]any{"applicationId": application.ID, "dryRun": true, "redirectUris": uriInputs(redirects, application.RedirectURIs)}},
		{"setAuthkitApplicationLogoutUris", map[string]any{"applicationId": application.ID, "dryRun": true, "logoutUris": uriInputs(logouts, application.LogoutURIs)}},
		{"setAuthkitApplicationWebOrigins", map[string]any{"applicationId": application.ID, "dryRun": true, "origins": sortedStrings(origins)}},
	} {
		if err := r.management.Mutate(ctx, validation.operation, plan.EnvironmentID.ValueString(), validation.variables); err != nil {
			resp.Diagnostics.AddError("Invalid AuthKit URL Configuration", err.Error())
			return
		}
	}
}

func authKitPlanUnknown(plan AuthKitConfigurationResourceModel) bool {
	return plan.EnvironmentID.IsUnknown() || plan.RedirectURIs.IsUnknown() || plan.LogoutURIs.IsUnknown() || plan.WebOrigins.IsUnknown()
}

func (r *AuthKitConfigurationResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan AuthKitConfigurationResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.apply(ctx, plan); err != nil {
		resp.Diagnostics.AddError("Unable to Configure AuthKit", err.Error())
		return
	}
	r.read(ctx, plan.EnvironmentID.ValueString(), &plan, &resp.Diagnostics)
	if !resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	}
}

func (r *AuthKitConfigurationResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state AuthKitConfigurationResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.read(ctx, state.EnvironmentID.ValueString(), &state, &resp.Diagnostics)
	if !resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	}
}

func (r *AuthKitConfigurationResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan AuthKitConfigurationResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.apply(ctx, plan); err != nil {
		resp.Diagnostics.AddError("Unable to Configure AuthKit", err.Error())
		return
	}
	r.read(ctx, plan.EnvironmentID.ValueString(), &plan, &resp.Diagnostics)
	if !resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	}
}

func (r *AuthKitConfigurationResource) apply(ctx context.Context, plan AuthKitConfigurationResourceModel) error {
	environmentID := plan.EnvironmentID.ValueString()
	application, err := r.management.DefaultAuthKitApplication(ctx, environmentID)
	if err != nil {
		return err
	}
	redirects, logouts, origins, diagnostics := authKitURLValues(ctx, plan)
	if diagnostics.HasError() {
		return fmt.Errorf("read AuthKit URL configuration: %s", diagnostics.Errors()[0].Detail())
	}

	// Application identity and owned URLs are applied before session and authentication policy.
	if err := r.management.Mutate(ctx, "updateAuthkitApplication", environmentID, map[string]any{
		"applicationId":    application.ID,
		"name":             plan.ApplicationName.ValueString(),
		"appHomepageUrl":   plan.HomepageURL.ValueString(),
		"initiateLoginUri": plan.InitiateLoginURI.ValueString(),
	}); err != nil {
		return err
	}
	for _, mutation := range []struct {
		operation string
		variables map[string]any
	}{
		{"setAuthkitApplicationRedirectUris", map[string]any{"applicationId": application.ID, "redirectUris": uriInputs(redirects, application.RedirectURIs)}},
		{"setAuthkitApplicationLogoutUris", map[string]any{"applicationId": application.ID, "logoutUris": uriInputs(logouts, application.LogoutURIs)}},
		{"setAuthkitApplicationWebOrigins", map[string]any{"applicationId": application.ID, "origins": sortedStrings(origins)}},
	} {
		if err := r.management.Mutate(ctx, mutation.operation, environmentID, mutation.variables); err != nil {
			return err
		}
	}
	if err := r.management.Mutate(ctx, "updateAuthkitApplication", environmentID, map[string]any{
		"applicationId":     application.ID,
		"accessTokenExpiry": plan.AccessTokenExpiry.ValueInt64(),
		"inactivityTimeout": plan.InactivityTimeout.ValueInt64(),
		"maxSessionTime":    plan.MaximumSession.ValueInt64(),
	}); err != nil {
		return err
	}
	composition := plan.PasswordCompositionRules.ValueBool()
	policy := map[string]any{
		"allowSignUp":         plan.AllowSignup.ValueBool(),
		"isAppleOauthEnabled": false,
		"isAuthkitClientIdMetadataDocumentEnabled":  false,
		"isAuthkitDynamicClientRegistrationEnabled": false,
		"isAuthkitIdpInitiatedSsoEnabled":           false,
		"isBitbucketOauthEnabled":                   false,
		"isDiscordOauthEnabled":                     false,
		"isGitLabOauthEnabled":                      false,
		"isGithubOauthEnabled":                      false,
		"isGoogleOauthEnabled":                      false,
		"isIntuitOauthEnabled":                      false,
		"isLinkedInOauthEnabled":                    false,
		"isMagicAuthEnabled":                        false,
		"isMicrosoftOauthEnabled":                   false,
		"isPasskeyAuthEnabled":                      false,
		"isPasskeyProgressiveEnrollmentEnabled":     false,
		"isPasswordAuthEnabled":                     true,
		"isPasswordHistoryEnabled":                  false,
		"isPasswordLowercaseRequired":               composition,
		"isPasswordNumberRequired":                  composition,
		"isPasswordPwnedRequired":                   plan.BreachedPasswordProtection.ValueBool(),
		"isPasswordSymbolRequired":                  composition,
		"isPasswordUppercaseRequired":               composition,
		"isSalesforceOauthEnabled":                  false,
		"isSlackOauthEnabled":                       false,
		"isSsoEnabled":                              false,
		"isVercelMarketplaceOauthEnabled":           false,
		"isVercelOauthEnabled":                      false,
		"isWaitlistEnabled":                         false,
		"isXeroOauthEnabled":                        false,
		"mfaEnabled":                                plan.MFA.ValueString(),
		"passwordMinimumLength":                     plan.PasswordMinimumLength.ValueInt64(),
	}
	if err := r.management.Mutate(ctx, "updateAuthkitSettings", environmentID, policy); err != nil {
		return err
	}
	return r.management.Mutate(ctx, "updateAuthkitSettings", environmentID, map[string]any{"isAuthkitEnabled": true})
}

func (r *AuthKitConfigurationResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state AuthKitConfigurationResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	environmentID := state.EnvironmentID.ValueString()
	if state.DeletionProtection.ValueBool() {
		resp.Diagnostics.AddError("AuthKit Reset Blocked", "Set deletion_protection = false before destroying this resource.")
		return
	}
	if os.Getenv("WORKOS_MCP_RESET_ENVIRONMENT_ID") != environmentID {
		resp.Diagnostics.AddAttributeError(path.Root("environment_id"), "AuthKit Reset Authorization Required", "Set WORKOS_MCP_RESET_ENVIRONMENT_ID to this exact environment ID for the destroy command.")
		return
	}
	application, err := r.management.DefaultAuthKitApplication(ctx, environmentID)
	if err != nil {
		resp.Diagnostics.AddError("Unable to Reset AuthKit", err.Error())
		return
	}
	// Sign-in is disabled before any owned URL is cleared.
	if err := r.management.Mutate(ctx, "updateAuthkitSettings", environmentID, map[string]any{"isAuthkitEnabled": false}); err != nil {
		resp.Diagnostics.AddError("Unable to Disable AuthKit", err.Error())
		return
	}
	for _, mutation := range []struct {
		operation string
		variables map[string]any
	}{
		{"setAuthkitApplicationRedirectUris", map[string]any{"applicationId": application.ID, "redirectUris": []any{}}},
		{"setAuthkitApplicationLogoutUris", map[string]any{"applicationId": application.ID, "logoutUris": []any{}}},
		{"setAuthkitApplicationWebOrigins", map[string]any{"applicationId": application.ID, "origins": []string{}}},
		{"updateAuthkitApplication", map[string]any{"applicationId": application.ID, "appHomepageUrl": "", "initiateLoginUri": ""}},
	} {
		if err := r.management.Mutate(ctx, mutation.operation, environmentID, mutation.variables); err != nil {
			resp.Diagnostics.AddError("Unable to Reset AuthKit", err.Error())
			return
		}
	}
}

func (r *AuthKitConfigurationResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("environment_id"), req.ID)...)
}

func (r *AuthKitConfigurationResource) read(ctx context.Context, environmentID string, state *AuthKitConfigurationResourceModel, diagnostics *diag.Diagnostics) {
	application, err := r.management.DefaultAuthKitApplication(ctx, environmentID)
	if err != nil {
		diagnostics.AddError("Unable to Read AuthKit Application", err.Error())
		return
	}
	settings, err := r.management.AuthKitSettings(ctx, environmentID)
	if err != nil {
		diagnostics.AddError("Unable to Read AuthKit Settings", err.Error())
		return
	}
	state.ID = types.StringValue(environmentID)
	state.EnvironmentID = types.StringValue(environmentID)
	state.ApplicationID = types.StringValue(application.ID)
	state.ClientID = types.StringValue(application.ClientID)
	state.ApplicationName = types.StringValue(application.Name)
	state.HomepageURL = nullableString(application.AppHomepageURL)
	state.InitiateLoginURI = nullableString(application.InitiateLoginURI)
	var setDiagnostics diag.Diagnostics
	state.RedirectURIs, setDiagnostics = types.SetValueFrom(ctx, types.StringType, uriStrings(application.RedirectURIs))
	diagnostics.Append(setDiagnostics...)
	state.LogoutURIs, setDiagnostics = types.SetValueFrom(ctx, types.StringType, uriStrings(application.LogoutURIs))
	diagnostics.Append(setDiagnostics...)
	state.WebOrigins, setDiagnostics = types.SetValueFrom(ctx, types.StringType, uriStrings(application.WebOrigins))
	diagnostics.Append(setDiagnostics...)
	if passwordOnly(settings) {
		state.AuthenticationMethod = types.StringValue("password")
	} else {
		state.AuthenticationMethod = types.StringValue("mixed")
	}
	state.AllowSignup = types.BoolValue(settings.AllowSignUp && !settings.IsWaitlistEnabled)
	state.MFA = types.StringValue(settings.MFAEnabled)
	state.PasswordMinimumLength = types.Int64Value(settings.PasswordMinimumLength)
	state.BreachedPasswordProtection = types.BoolValue(settings.IsPasswordPwnedRequired)
	state.PasswordCompositionRules = types.BoolValue(settings.IsPasswordLowercaseRequired || settings.IsPasswordNumberRequired || settings.IsPasswordSymbolRequired || settings.IsPasswordUppercaseRequired)
	state.AccessTokenExpiry = types.Int64Value(application.AccessTokenExpiry)
	state.InactivityTimeout = types.Int64Value(application.InactivityTimeout)
	state.MaximumSession = types.Int64Value(application.MaxSessionTime)
	state.EmailVerificationEnabled = types.BoolValue(settings.IsEmailVerificationRequired)
	if state.DeletionProtection.IsNull() || state.DeletionProtection.IsUnknown() {
		state.DeletionProtection = types.BoolValue(true)
	}
}

func authKitURLValues(ctx context.Context, plan AuthKitConfigurationResourceModel) ([]string, []string, []string, diag.Diagnostics) {
	var redirects, logouts, origins []string
	var diagnostics diag.Diagnostics
	diagnostics.Append(plan.RedirectURIs.ElementsAs(ctx, &redirects, false)...)
	diagnostics.Append(plan.LogoutURIs.ElementsAs(ctx, &logouts, false)...)
	diagnostics.Append(plan.WebOrigins.ElementsAs(ctx, &origins, false)...)
	return redirects, logouts, origins, diagnostics
}

func uriInputs(desired []string, existing []client.AuthKitURI) []map[string]any {
	desired = sortedStrings(desired)
	byURI := make(map[string]client.AuthKitURI, len(existing))
	defaultURI := ""
	for _, value := range existing {
		uri := authKitURIString(value)
		byURI[uri] = value
		if value.Default || value.IsDefault {
			defaultURI = uri
		}
	}
	if defaultURI == "" && len(desired) != 0 {
		defaultURI = desired[0]
	}
	result := make([]map[string]any, 0, len(desired))
	for _, uri := range desired {
		item := map[string]any{"uri": uri, "isDefault": uri == defaultURI}
		if existingValue := byURI[uri]; existingValue.ID != "" {
			item["id"] = existingValue.ID
		}
		result = append(result, item)
	}
	return result
}

func sortedStrings(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}

func uriStrings(values []client.AuthKitURI) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if uri := authKitURIString(value); uri != "" {
			result = append(result, uri)
		}
	}
	return sortedStrings(result)
}

func authKitURIString(value client.AuthKitURI) string {
	if value.URI != "" {
		return value.URI
	}
	return value.Origin
}

func nullableString(value *string) types.String {
	if value == nil {
		return types.StringValue("")
	}
	return types.StringValue(*value)
}

func passwordOnly(settings *client.AuthKitSettings) bool {
	return settings.IsAuthKitEnabled && settings.IsPasswordAuthEnabled && !settings.IsWaitlistEnabled &&
		!settings.IsAuthKitIDPInitiatedSSOEnabled && !settings.IsAppleOAuthEnabled && !settings.IsBitbucketOAuthEnabled &&
		!settings.IsDiscordOAuthEnabled && !settings.IsGitHubOAuthEnabled && !settings.IsGitLabOAuthEnabled &&
		!settings.IsGoogleOAuthEnabled && !settings.IsIntuitOAuthEnabled && !settings.IsLinkedInOAuthEnabled &&
		!settings.IsMicrosoftOAuthEnabled && !settings.IsSalesforceOAuthEnabled && !settings.IsSlackOAuthEnabled &&
		!settings.IsVercelMarketplaceOAuthEnabled && !settings.IsVercelOAuthEnabled && !settings.IsXeroOAuthEnabled &&
		!settings.IsMagicAuthEnabled && !settings.IsPasskeyAuthEnabled && !settings.IsPasskeyProgressiveEnrollment && !settings.IsSSOEnabled
}
