// Package provider implements the LastPass Terraform provider.
package provider

import (
	"context"
	"fmt"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Groupe-Hevea/terraform-provider-lastpass/internal/lastpass"
)

type lastpassProvider struct {
	version string
	options []lastpass.Option
}

type providerModel struct {
	Username types.String `tfsdk:"username"`
	Password types.String `tfsdk:"password"`
}

// New returns the provider factory. options reach the LastPass client; tests
// use them to point it at a fake server.
func New(version string, options ...lastpass.Option) func() provider.Provider {
	return func() provider.Provider {
		return &lastpassProvider{version: version, options: options}
	}
}

func (p *lastpassProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "lastpass"
	resp.Version = p.version
}

func (p *lastpassProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads and manages LastPass vault entries. The provider logs in only when a resource or data source needs it.",
		Attributes: map[string]schema.Attribute{
			"username": schema.StringAttribute{
				Optional:    true,
				Description: "LastPass login e-mail. Defaults to the LASTPASS_USER environment variable.",
			},
			"password": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "LastPass master password. Defaults to the LASTPASS_PASSWORD environment variable.",
			},
		},
	}
}

func (p *lastpassProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	v := &vault{
		username: valueOrEnv(config.Username, "LASTPASS_USER"),
		password: valueOrEnv(config.Password, "LASTPASS_PASSWORD"),
		options:  p.options,
	}
	resp.ResourceData = v
	resp.DataSourceData = v
}

func (p *lastpassProvider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{newSecretResource}
}

func (p *lastpassProvider) DataSources(context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{newSecretDataSource}
}

func valueOrEnv(value types.String, variable string) string {
	if value.IsNull() || value.IsUnknown() {
		return os.Getenv(variable)
	}
	return value.ValueString()
}

// vaultFromProviderData recovers what Configure handed over. providerData is
// nil while Terraform validates a configuration, before Configure ran.
func vaultFromProviderData(providerData any) (*vault, error) {
	if providerData == nil {
		return nil, nil
	}
	v, ok := providerData.(*vault)
	if !ok {
		return nil, fmt.Errorf("unexpected provider data %T", providerData)
	}
	return v, nil
}
