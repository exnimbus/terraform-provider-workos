// Copyright (c) OSO DevOps
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/exnimbus/terraform-provider-workos/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var _ resource.Resource = &RedirectURIResource{}
var _ resource.ResourceWithImportState = &RedirectURIResource{}

func NewRedirectURIResource() resource.Resource {
	return &RedirectURIResource{}
}

type RedirectURIResource struct {
	client *client.Client
}

type RedirectURIResourceModel struct {
	ID        types.String `tfsdk:"id"`
	URI       types.String `tfsdk:"uri"`
	Default   types.Bool   `tfsdk:"default"`
	CreatedAt types.String `tfsdk:"created_at"`
	UpdatedAt types.String `tfsdk:"updated_at"`
}

func (r *RedirectURIResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_redirect_uri"
}

func (r *RedirectURIResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a WorkOS AuthKit redirect URI.",
		MarkdownDescription: `
Manages a WorkOS AuthKit redirect URI in the current WorkOS environment.

Redirect URIs are immutable in the WorkOS API. Changing ` + "`uri`" + ` forces Terraform
to replace the resource.

## Example Usage

` + "```hcl" + `
resource "workos_redirect_uri" "production_callback" {
  uri = "https://app.example.com/api/auth/callback"
}
` + "```" + `

## Import

AuthKit redirect URIs can be imported using their WorkOS ID:

` + "```shell" + `
terraform import workos_redirect_uri.example redirect_uri_01H00000000000000000000000
` + "```" + `
`,
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description:         "The unique identifier of the AuthKit redirect URI.",
				MarkdownDescription: "The unique identifier of the AuthKit redirect URI.",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"uri": schema.StringAttribute{
				Description:         "The redirect URI.",
				MarkdownDescription: "The redirect URI. Changing this value forces replacement.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"default": schema.BoolAttribute{
				Description:         "Whether this is the default redirect URI.",
				MarkdownDescription: "Whether this is the default redirect URI.",
				Computed:            true,
			},
			"created_at": schema.StringAttribute{
				Description:         "The timestamp when the redirect URI was created.",
				MarkdownDescription: "The timestamp when the redirect URI was created (RFC3339 format).",
				Computed:            true,
			},
			"updated_at": schema.StringAttribute{
				Description:         "The timestamp when the redirect URI was last updated.",
				MarkdownDescription: "The timestamp when the redirect URI was last updated (RFC3339 format).",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

func (r *RedirectURIResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	c, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *client.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	r.client = c
}

func (r *RedirectURIResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan RedirectURIResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	redirectURI, err := r.client.CreateRedirectURI(ctx, &client.RedirectURICreateRequest{
		URI: plan.URI.ValueString(),
	})
	if err != nil {
		if isLikelyDuplicateWorkOSError(err) {
			resp.Diagnostics.AddAttributeError(
				path.Root("uri"),
				"AuthKit Redirect URI Already Exists",
				"WorkOS reported that this redirect URI already exists. Import the existing redirect URI into Terraform state instead of creating a duplicate. "+
					"Original error: "+err.Error(),
			)
			return
		}
		resp.Diagnostics.AddError("Error Creating AuthKit Redirect URI", "Could not create AuthKit redirect URI: "+err.Error())
		return
	}

	redirectURIToState(&plan, redirectURI)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *RedirectURIResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state RedirectURIResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	redirectURI, err := r.client.GetRedirectURI(ctx, state.ID.ValueString())
	if err != nil {
		if client.IsNotFound(err) {
			tflog.Info(ctx, "AuthKit redirect URI not found, removing from state", map[string]any{"id": state.ID.ValueString()})
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error Reading AuthKit Redirect URI", "Could not read AuthKit redirect URI: "+err.Error())
		return
	}

	redirectURIToState(&state, redirectURI)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *RedirectURIResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError(
		"AuthKit Redirect URI Update Is Not Supported",
		"Redirect URIs are immutable in the WorkOS API. Changing the uri value should plan a replacement.",
	)
}

func (r *RedirectURIResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state RedirectURIResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.client.DeleteRedirectURI(ctx, state.ID.ValueString())
	if err != nil {
		if client.IsNotFound(err) {
			tflog.Info(ctx, "AuthKit redirect URI already deleted", map[string]any{"id": state.ID.ValueString()})
			return
		}
		resp.Diagnostics.AddError("Error Deleting AuthKit Redirect URI", "Could not delete AuthKit redirect URI: "+err.Error())
	}
}

func (r *RedirectURIResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func redirectURIToState(state *RedirectURIResourceModel, redirectURI *client.RedirectURI) {
	state.ID = types.StringValue(redirectURI.ID)
	state.URI = types.StringValue(redirectURI.URI)
	state.Default = types.BoolValue(redirectURI.Default)
	state.CreatedAt = timeString(redirectURI.CreatedAt)
	state.UpdatedAt = timeString(redirectURI.UpdatedAt)
}

func timeString(value time.Time) types.String {
	if value.IsZero() {
		return types.StringNull()
	}
	return types.StringValue(value.Format(time.RFC3339))
}

func isLikelyDuplicateWorkOSError(err error) bool {
	var apiErr *client.APIError
	isValidationError := errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusUnprocessableEntity
	if !client.IsConflict(err) && !client.IsBadRequest(err) && !isValidationError {
		return false
	}

	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "already") || strings.Contains(msg, "exists") || strings.Contains(msg, "duplicate")
}
