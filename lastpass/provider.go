package lastpass

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/Groupe-Hevea/terraform-provider-lastpass/api"
)

// Provider config
type config struct {
	Username string
	Password string
}

// Provider is the root of the lastpass provider
func Provider() *schema.Provider {
	return &schema.Provider{
		ResourcesMap: map[string]*schema.Resource{
			"lastpass_secret": ResourceSecret(),
		},
		DataSourcesMap: map[string]*schema.Resource{
			"lastpass_secret": DataSourceSecret(),
		},
		Schema: map[string]*schema.Schema{
			"username": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Lastpass login e-mail (Only needed if provider is really used)",
				DefaultFunc: schema.EnvDefaultFunc("LASTPASS_USER", nil),
			},
			"password": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Lastpass login password (Only needed if provider is really used)",
				DefaultFunc: schema.EnvDefaultFunc("LASTPASS_PASSWORD", nil),
			},
		},
		ConfigureContextFunc: providerConfigure,
	}
}

func providerConfigure(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
	var diags diag.Diagnostics

	username := d.Get("username").(string)
	password := d.Get("password").(string)

	credentialsProvided := username != "" && password != ""

	client := api.Client{
		Username:            username,
		Password:            password,
		CredentialsProvided: credentialsProvided,
	}

	return &client, diags
}
