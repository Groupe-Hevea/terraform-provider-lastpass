package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = (*secretDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*secretDataSource)(nil)
)

type secretDataSource struct {
	vault *vault
}

type secretDataSourceModel struct {
	secretModel
	CustomFields types.Map `tfsdk:"custom_fields"`
}

func newSecretDataSource() datasource.DataSource {
	return &secretDataSource{}
}

func (d *secretDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_secret"
}

func (d *secretDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads a LastPass vault entry by its ID.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Required:    true,
				Description: "Identifier of the entry: a number, shown by LastPass in the entry's details.",
			},
			"name":              schema.StringAttribute{Computed: true, Description: "Full path of the entry: `<shared folder>/<folder>/<name>`."},
			"fullname":          schema.StringAttribute{Computed: true, Description: "Same as `name`."},
			"username":          schema.StringAttribute{Computed: true},
			"password":          schema.StringAttribute{Computed: true, Sensitive: true},
			"last_modified_gmt": schema.StringAttribute{Computed: true, Description: "Last modification, in seconds since the epoch."},
			"last_touch":        schema.StringAttribute{Computed: true, Description: "Last access, in seconds since the epoch."},
			"group":             schema.StringAttribute{Computed: true, Description: "Folder of the entry inside its shared folder."},
			"url":               schema.StringAttribute{Computed: true},
			"note":              schema.StringAttribute{Computed: true, Sensitive: true, Description: "A multi-line note is returned with a final newline."},
			"custom_fields": schema.MapAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Sensitive:   true,
				Description: "Fields of a typed secure note (server, SSH key, ...), by name. Empty for other entries.",
			},
		},
	}
}

func (d *secretDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	v, err := vaultFromProviderData(req.ProviderData)
	if err != nil {
		resp.Diagnostics.AddError("Provider misconfigured", err.Error())
	}
	d.vault = v
}

func (d *secretDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config secretDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := config.ID.ValueString()
	if !validID(id, &resp.Diagnostics) {
		return
	}
	account, err := d.vault.get(ctx, id)
	if err != nil {
		resp.Diagnostics.AddError("Cannot read the LastPass entry", err.Error())
		return
	}
	if account == nil {
		resp.Diagnostics.AddError("LastPass entry not found", "No entry has the ID "+id+", or it is not visible to this account.")
		return
	}

	secret := modelFromAccount(account, types.StringNull())
	fields, diags := types.MapValueFrom(ctx, types.StringType, customFields(secret.Note.ValueString()))
	resp.Diagnostics.Append(diags...)
	resp.Diagnostics.Append(resp.State.Set(ctx, secretDataSourceModel{secretModel: secret, CustomFields: fields})...)
}
