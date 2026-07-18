// Copyright (c) OSO DevOps
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/exnimbus/terraform-provider-workos/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var _ resource.Resource = &CORSOriginResource{}
var _ resource.ResourceWithImportState = &CORSOriginResource{}

func NewCORSOriginResource() resource.Resource {
	return &CORSOriginResource{}
}

type CORSOriginResource struct {
	client *client.Client
}

type CORSOriginResourceModel struct {
	ID        types.String `tfsdk:"id"`
	Origin    types.String `tfsdk:"origin"`
	CreatedAt types.String `tfsdk:"created_at"`
	UpdatedAt types.String `tfsdk:"updated_at"`
}

func (r *CORSOriginResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cors_origin"
}

func (r *CORSOriginResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a WorkOS AuthKit CORS origin.",
		MarkdownDescription: `
Manages a WorkOS AuthKit CORS origin in the current WorkOS environment.

CORS origins are immutable in the WorkOS API. Changing ` + "`origin`" + ` forces
Terraform to replace the resource.

## Example Usage

` + "```hcl" + `
resource "workos_cors_origin" "production_web" {
  origin = "https://app.example.com"
}
` + "```" + `

## Import

AuthKit CORS origins can be imported using their WorkOS ID:

` + "```shell" + `
terraform import workos_cors_origin.example cors_origin_01H00000000000000000000000
` + "```" + `
`,
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description:         "The unique identifier of the AuthKit CORS origin.",
				MarkdownDescription: "The unique identifier of the AuthKit CORS origin.",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"origin": schema.StringAttribute{
				Description:         "The CORS origin.",
				MarkdownDescription: "The CORS origin. Changing this value forces replacement.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"created_at": schema.StringAttribute{
				Description:         "The timestamp when the CORS origin was created.",
				MarkdownDescription: "The timestamp when the CORS origin was created (RFC3339 format).",
				Computed:            true,
			},
			"updated_at": schema.StringAttribute{
				Description:         "The timestamp when the CORS origin was last updated.",
				MarkdownDescription: "The timestamp when the CORS origin was last updated (RFC3339 format).",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

func (r *CORSOriginResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *CORSOriginResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan CORSOriginResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	origin, err := r.client.CreateCORSOrigin(ctx, &client.CORSOriginCreateRequest{
		Origin: plan.Origin.ValueString(),
	})
	if err != nil {
		if isLikelyDuplicateWorkOSError(err) {
			resp.Diagnostics.AddAttributeError(
				path.Root("origin"),
				"AuthKit CORS Origin Already Exists",
				"WorkOS reported that this CORS origin already exists. Import the existing CORS origin into Terraform state instead of creating a duplicate. "+
					"Original error: "+err.Error(),
			)
			return
		}
		resp.Diagnostics.AddError("Error Creating AuthKit CORS Origin", "Could not create AuthKit CORS origin: "+err.Error())
		return
	}

	corsOriginToState(&plan, origin)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *CORSOriginResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CORSOriginResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	origin, err := r.client.GetCORSOrigin(ctx, state.ID.ValueString())
	if err != nil {
		if client.IsNotFound(err) {
			tflog.Info(ctx, "AuthKit CORS origin not found, removing from state", map[string]any{"id": state.ID.ValueString()})
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error Reading AuthKit CORS Origin", "Could not read AuthKit CORS origin: "+err.Error())
		return
	}

	corsOriginToState(&state, origin)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *CORSOriginResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError(
		"AuthKit CORS Origin Update Is Not Supported",
		"CORS origins are immutable in the WorkOS API. Changing the origin value should plan a replacement.",
	)
}

func (r *CORSOriginResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CORSOriginResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.client.DeleteCORSOrigin(ctx, state.ID.ValueString())
	if err != nil {
		if client.IsNotFound(err) {
			tflog.Info(ctx, "AuthKit CORS origin already deleted", map[string]any{"id": state.ID.ValueString()})
			return
		}
		resp.Diagnostics.AddError("Error Deleting AuthKit CORS Origin", "Could not delete AuthKit CORS origin: "+err.Error())
	}
}

func (r *CORSOriginResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func corsOriginToState(state *CORSOriginResourceModel, origin *client.CORSOrigin) {
	state.ID = types.StringValue(origin.ID)
	state.Origin = types.StringValue(origin.Origin)
	state.CreatedAt = timeString(origin.CreatedAt)
	state.UpdatedAt = timeString(origin.UpdatedAt)
}
