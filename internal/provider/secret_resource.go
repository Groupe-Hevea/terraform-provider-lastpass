package provider

import (
	"context"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Groupe-Hevea/terraform-provider-lastpass/internal/lastpass"
)

var (
	_ resource.Resource                = (*secretResource)(nil)
	_ resource.ResourceWithConfigure   = (*secretResource)(nil)
	_ resource.ResourceWithImportState = (*secretResource)(nil)
)

type secretResource struct {
	vault *vault
}

type secretResourceModel struct {
	ID              types.String `tfsdk:"id"`
	Name            types.String `tfsdk:"name"`
	Fullname        types.String `tfsdk:"fullname"`
	Username        types.String `tfsdk:"username"`
	Password        types.String `tfsdk:"password"`
	LastModifiedGMT types.String `tfsdk:"last_modified_gmt"`
	LastTouch       types.String `tfsdk:"last_touch"`
	Group           types.String `tfsdk:"group"`
	URL             types.String `tfsdk:"url"`
	Note            types.String `tfsdk:"note"`
}

func newSecretResource() resource.Resource {
	return &secretResource{}
}

func (r *secretResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_secret"
}

func (r *secretResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	// An attribute left out of the configuration keeps the value LastPass holds.
	keep := []planmodifier.String{stringplanmodifier.UseStateForUnknown()}

	resp.Schema = schema.Schema{
		Description: "A LastPass vault entry.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "Identifier assigned by LastPass.",
				PlanModifiers: keep,
			},
			"name": schema.StringAttribute{
				Required: true,
				Description: "Full path of the entry: `<shared folder>/<folder>/<name>`, the first two being optional. " +
					"A shared folder is recognised by its `Shared-` prefix. Changing it recreates the entry.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"fullname": schema.StringAttribute{
				Computed:      true,
				Description:   "Same as `name`.",
				PlanModifiers: keep,
			},
			"username": schema.StringAttribute{
				Optional:      true,
				Computed:      true,
				PlanModifiers: keep,
			},
			"password": schema.StringAttribute{
				Optional:      true,
				Computed:      true,
				Sensitive:     true,
				PlanModifiers: keep,
			},
			"last_modified_gmt": schema.StringAttribute{
				Computed:    true,
				Description: "Last modification, in seconds since the epoch.",
			},
			"last_touch": schema.StringAttribute{
				Computed:    true,
				Description: "Last access, in seconds since the epoch.",
			},
			"group": schema.StringAttribute{
				Computed:      true,
				Description:   "Folder of the entry inside its shared folder.",
				PlanModifiers: keep,
			},
			"url": schema.StringAttribute{
				Optional:      true,
				Computed:      true,
				PlanModifiers: keep,
			},
			"note": schema.StringAttribute{
				Optional:      true,
				Computed:      true,
				Sensitive:     true,
				Description:   "The secret note content. LastPass stores it without trailing newline.",
				PlanModifiers: keep,
			},
		},
	}
}

func (r *secretResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	v, err := vaultFromProviderData(req.ProviderData)
	if err != nil {
		resp.Diagnostics.AddError("Provider misconfigured", err.Error())
	}
	r.vault = v
}

func (r *secretResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan secretResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	created, err := r.vault.create(ctx, accountFromPlan(plan))
	if err != nil {
		resp.Diagnostics.AddError("Cannot create the LastPass entry", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, modelFromAccount(created, plan.Note))...)
}

func (r *secretResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state secretResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	account, err := r.vault.get(ctx, state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Cannot read the LastPass entry", err.Error())
		return
	}
	if account == nil {
		resp.State.RemoveResource(ctx)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, modelFromAccount(account, state.Note))...)
}

func (r *secretResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan secretResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	updated, err := r.vault.update(ctx, accountFromPlan(plan))
	if err != nil {
		resp.Diagnostics.AddError("Cannot update the LastPass entry", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, modelFromAccount(updated, plan.Note))...)
}

func (r *secretResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state secretResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.vault.delete(ctx, state.ID.ValueString()); err != nil {
		resp.Diagnostics.AddError("Cannot delete the LastPass entry", err.Error())
	}
}

func (r *secretResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if !isLastPassID(req.ID) {
		resp.Diagnostics.AddError("Not a valid LastPass ID", "The ID of a LastPass entry is a number, got: "+req.ID)
		return
	}
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// accountFromPlan builds the entry to write. The ID is unknown on creation,
// which reads as an empty string: the vault assigns one.
func accountFromPlan(plan secretResourceModel) lastpass.Account {
	share, group, name := splitFullname(plan.Name.ValueString())
	return lastpass.Account{
		ID:       plan.ID.ValueString(),
		Share:    share,
		Group:    group,
		Name:     name,
		Username: plan.Username.ValueString(),
		Password: plan.Password.ValueString(),
		URL:      plan.URL.ValueString(),
		Notes:    storedNote(plan.Note.ValueString()),
	}
}

// modelFromAccount maps an entry to the resource state. known is the note
// Terraform already holds (planned or prior): it is kept when LastPass holds
// the same note up to trailing newlines, see storedNote.
func modelFromAccount(account *lastpass.Account, known types.String) secretResourceModel {
	note := exposedNote(account.Notes)
	if !known.IsNull() && !known.IsUnknown() && sameNote(known.ValueString(), account.Notes) {
		note = known.ValueString()
	}
	return secretResourceModel{
		ID:              types.StringValue(account.ID),
		Name:            types.StringValue(fullname(account)),
		Fullname:        types.StringValue(fullname(account)),
		Username:        types.StringValue(account.Username),
		Password:        types.StringValue(account.Password),
		LastModifiedGMT: types.StringValue(account.LastModifiedGMT),
		LastTouch:       types.StringValue(account.LastTouch),
		Group:           types.StringValue(account.Group),
		URL:             types.StringValue(account.URL),
		Note:            types.StringValue(note),
	}
}

func isLastPassID(id string) bool {
	_, err := strconv.ParseUint(id, 10, 64)
	return err == nil
}
