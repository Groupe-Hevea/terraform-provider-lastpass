package provider

import (
	"context"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Groupe-Hevea/terraform-provider-lastpass/internal/lastpass"
)

var (
	_ resource.Resource                = (*secretResource)(nil)
	_ resource.ResourceWithConfigure   = (*secretResource)(nil)
	_ resource.ResourceWithImportState = (*secretResource)(nil)
	_ resource.ResourceWithModifyPlan  = (*secretResource)(nil)
)

type secretResource struct {
	vault *vault
}

// secretModel is the state of a vault entry, shared by the resource and the
// data source.
type secretModel struct {
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
	// What the configuration does not say is taken from the prior state.
	keep := []planmodifier.String{stringplanmodifier.UseStateForUnknown()}
	// The same goes for an optional argument set to "".
	optional := []planmodifier.String{stringplanmodifier.UseStateForUnknown(), emptyKeepsState{}}

	resp.Schema = schema.Schema{
		Description: "A LastPass vault entry. Creating an entry whose name is already taken adopts the existing entry instead of adding a namesake.",
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
				Validators:    []validator.String{entryPath{}},
			},
			"fullname": schema.StringAttribute{
				Computed:      true,
				Description:   "Same as `name`.",
				PlanModifiers: keep,
			},
			"username": schema.StringAttribute{
				Optional:      true,
				Computed:      true,
				PlanModifiers: optional,
			},
			"password": schema.StringAttribute{
				Optional:      true,
				Computed:      true,
				Sensitive:     true,
				PlanModifiers: optional,
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
				PlanModifiers: optional,
			},
			"note": schema.StringAttribute{
				Optional:      true,
				Computed:      true,
				Sensitive:     true,
				Description:   "The secret note content. The provider stores it without trailing newlines.",
				PlanModifiers: optional,
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

// ModifyPlan drops an update that would change nothing. The framework marks
// the timestamps as unknown as soon as the configuration differs from the
// state, before emptyKeepsState has a say: when every argument ends up
// planned at its current value, the timestamps are known too.
func (r *secretResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.State.Raw.IsNull() || req.Plan.Raw.IsNull() {
		return // creation or destruction
	}
	var plan, state secretModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if plan.Name.Equal(state.Name) && plan.Username.Equal(state.Username) && plan.Password.Equal(state.Password) &&
		plan.URL.Equal(state.URL) && plan.Note.Equal(state.Note) {
		plan.LastModifiedGMT, plan.LastTouch = state.LastModifiedGMT, state.LastTouch
		resp.Diagnostics.Append(resp.Plan.Set(ctx, plan)...)
	}
}

func (r *secretResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan secretModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	desired := accountFromPlan(plan)
	created, adopted, err := r.vault.create(ctx, desired, func(existing lastpass.Account) lastpass.Account {
		// An adopted entry keeps what the configuration does not set.
		merged := desired
		merged.ID, merged.Reprompt = existing.ID, existing.Reprompt
		for _, attribute := range []struct {
			planned  types.String
			dst, src *string
		}{
			{plan.Username, &merged.Username, &existing.Username},
			{plan.Password, &merged.Password, &existing.Password},
			{plan.URL, &merged.URL, &existing.URL},
			{plan.Note, &merged.Notes, &existing.Notes},
		} {
			if attribute.planned.IsUnknown() {
				*attribute.dst = *attribute.src
			}
		}
		return merged
	})
	// The entry is recorded as soon as LastPass holds it, error or not:
	// losing its ID would make the next run create a namesake.
	if created != nil {
		resp.Diagnostics.Append(resp.State.Set(ctx, modelFromAccount(created, plan.Note))...)
	}
	if err != nil {
		resp.Diagnostics.AddError("Cannot create the LastPass entry", err.Error())
		return
	}
	if adopted {
		resp.Diagnostics.AddWarning("Existing LastPass entry adopted",
			"An entry named "+plan.Name.ValueString()+" already existed (ID "+created.ID+"). It was updated and is now managed by this resource, instead of creating a second entry with the same name.")
	}
}

func (r *secretResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state secretModel
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
	var plan secretModel
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
	var state secretModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.vault.delete(ctx, state.ID.ValueString()); err != nil {
		resp.Diagnostics.AddError("Cannot delete the LastPass entry", err.Error())
	}
}

func (r *secretResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if !validID(req.ID, &resp.Diagnostics) {
		return
	}
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// accountFromPlan builds the entry to write. The ID is unknown on creation,
// which reads as an empty string: the vault assigns one.
func accountFromPlan(plan secretModel) lastpass.Account {
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

// modelFromAccount maps an entry to its Terraform state. known is the note
// Terraform already holds (planned or prior): it is kept when LastPass holds
// the same note up to trailing newlines, see storedNote.
func modelFromAccount(account *lastpass.Account, known types.String) secretModel {
	note := exposedNote(account.Notes)
	if !known.IsNull() && !known.IsUnknown() && sameNote(known.ValueString(), account.Notes) {
		note = known.ValueString()
	}
	return secretModel{
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

// validID reports whether id can be a LastPass entry ID, and says so if not.
func validID(id string, diags *diag.Diagnostics) bool {
	if _, err := strconv.ParseUint(id, 10, 64); err != nil {
		diags.AddError("Not a valid LastPass ID", "The ID of a LastPass entry is a number, got: "+id)
		return false
	}
	return true
}

// emptyKeepsState plans the prior value for an optional argument set to "".
// The provider's predecessor read "" as "not set"; configurations rely on
// it, typically through a variable defaulting to "", and would otherwise
// blank the field in LastPass.
type emptyKeepsState struct{}

func (emptyKeepsState) Description(context.Context) string {
	return `An empty string keeps the value the entry already has.`
}

func (m emptyKeepsState) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (emptyKeepsState) PlanModifyString(_ context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() || req.ConfigValue.ValueString() != "" {
		return
	}
	if !req.StateValue.IsNull() {
		resp.PlanValue = req.StateValue
	}
}

// entryPath rejects names that LastPass would store under another path, such
// as a leading or doubled "/": Terraform would never see the name it planned.
type entryPath struct{}

func (entryPath) Description(context.Context) string {
	return "Must be `<shared folder>/<folder>/<name>` with a non-empty name."
}

func (v entryPath) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (entryPath) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	value := req.ConfigValue.ValueString()
	share, group, name := splitFullname(value)
	if name == "" || fullname(&lastpass.Account{Share: share, Group: group, Name: name}) != value {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid entry name",
			"The name must be `<shared folder>/<folder>/<name>`, the first two being optional: it cannot start or end with \"/\", nor have an empty shared folder or folder. Got: "+value)
	}
}
