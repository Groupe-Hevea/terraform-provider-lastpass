package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/Groupe-Hevea/terraform-provider-lastpass/internal/lastpass"
	"github.com/Groupe-Hevea/terraform-provider-lastpass/internal/lastpass/lastpasstest"
)

// These tests drive the provider through a real Terraform binary, against the
// fake LastPass server. They need `terraform` on the PATH.

func testProvider(t *testing.T, server *lastpasstest.Server) map[string]func() (tfprotov6.ProviderServer, error) {
	t.Setenv("LASTPASS_USER", testUsername)
	t.Setenv("LASTPASS_PASSWORD", testPassword)
	return map[string]func() (tfprotov6.ProviderServer, error){
		"lastpass": providerserver.NewProtocol6WithError(New("test", lastpass.WithBaseURL(server.URL))()),
	}
}

func stored(t *testing.T, server *lastpasstest.Server, name string) lastpass.Account {
	t.Helper()
	for _, account := range server.Accounts() {
		if account.Name == name {
			return account
		}
	}
	t.Fatalf("no entry named %q on the server", name)
	return lastpass.Account{}
}

const secretConfig = `
resource "lastpass_secret" "key" {
  name     = "Shared-Infra/tfstates/aws_iam_key"
  username = "AKIAEXAMPLE"
  password = %q
  note     = <<-EOL
    Username is the access key and password is the secret key
    Géré par terraform
  EOL
}
`

func TestSecretResourceLifecycle(t *testing.T) {
	server := lastpasstest.New(t, testUsername, testPassword)
	server.AddShare("Shared-Infra", false)
	const address = "lastpass_secret.key"
	const note = "Username is the access key and password is the secret key\nGéré par terraform\n"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProvider(t, server),
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(secretConfig, "first"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(address, "name", "Shared-Infra/tfstates/aws_iam_key"),
					resource.TestCheckResourceAttr(address, "fullname", "Shared-Infra/tfstates/aws_iam_key"),
					resource.TestCheckResourceAttr(address, "group", "tfstates"),
					resource.TestCheckResourceAttr(address, "username", "AKIAEXAMPLE"),
					resource.TestCheckResourceAttr(address, "password", "first"),
					resource.TestCheckResourceAttr(address, "url", ""),
					resource.TestCheckResourceAttr(address, "note", note),
					resource.TestMatchResourceAttr(address, "id", regexp.MustCompile(`^\d+$`)),
					resource.TestCheckResourceAttrSet(address, "last_modified_gmt"),
					func(*terraform.State) error {
						account := stored(t, server, "aws_iam_key")
						if account.Share != "Shared-Infra" || account.Group != "tfstates" {
							t.Errorf("entry stored in %q / %q", account.Share, account.Group)
						}
						// LastPass holds the note without its trailing newline.
						if want := "Username is the access key and password is the secret key\nGéré par terraform"; account.Notes != want {
							t.Errorf("stored note = %q, want %q", account.Notes, want)
						}
						return nil
					},
				),
			},
			{
				// Nothing changed: the heredoc's trailing newline must not show as a diff.
				Config:           fmt.Sprintf(secretConfig, "first"),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}},
			},
			{
				Config: fmt.Sprintf(secretConfig, "rotated"),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(address, plancheck.ResourceActionUpdate),
				}},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(address, "password", "rotated"),
					resource.TestCheckResourceAttr(address, "note", note),
					func(*terraform.State) error {
						if got := stored(t, server, "aws_iam_key").Password; got != "rotated" {
							t.Errorf("stored password = %q", got)
						}
						return nil
					},
				),
			},
			{
				ResourceName:      address,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})

	if remaining := server.Accounts(); len(remaining) != 0 {
		t.Errorf("destroy left %d entries on the server", len(remaining))
	}
}

func TestSecretResourceFollowsChangesMadeElsewhere(t *testing.T) {
	server := lastpasstest.New(t, testUsername, testPassword)
	const config = `
resource "lastpass_secret" "site" {
  name     = "site"
  password = "from terraform"
}
`
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProvider(t, server),
		Steps: []resource.TestStep{
			{Config: config},
			{
				// Someone edits the entry in LastPass: the next plan puts the password back
				// and leaves alone what the configuration does not set.
				PreConfig: func() {
					account := stored(t, server, "site")
					client, err := lastpass.Login(t.Context(), testUsername, testPassword, lastpass.WithBaseURL(server.URL))
					if err != nil {
						t.Fatal(err)
					}
					v, err := client.Vault(t.Context())
					if err != nil {
						t.Fatal(err)
					}
					account.Password = "changed by hand"
					account.Username = "set by hand"
					if err := client.Update(t.Context(), v, &account); err != nil {
						t.Fatal(err)
					}
				},
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("lastpass_secret.site", "password", "from terraform"),
					resource.TestCheckResourceAttr("lastpass_secret.site", "username", "set by hand"),
				),
			},
			{
				// The entry is deleted in LastPass: Terraform recreates it.
				PreConfig: func() {
					account := stored(t, server, "site")
					client, err := lastpass.Login(t.Context(), testUsername, testPassword, lastpass.WithBaseURL(server.URL))
					if err != nil {
						t.Fatal(err)
					}
					v, err := client.Vault(t.Context())
					if err != nil {
						t.Fatal(err)
					}
					if err := client.Delete(t.Context(), v, &account); err != nil {
						t.Fatal(err)
					}
				},
				Config: config,
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction("lastpass_secret.site", plancheck.ResourceActionCreate),
				}},
			},
		},
	})
}

func TestSecretResourceRenameReplacesTheEntry(t *testing.T) {
	server := lastpasstest.New(t, testUsername, testPassword)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProvider(t, server),
		Steps: []resource.TestStep{
			{Config: `resource "lastpass_secret" "s" { name = "folder/before" }`},
			{
				Config: `resource "lastpass_secret" "s" { name = "folder/after" }`,
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction("lastpass_secret.s", plancheck.ResourceActionDestroyBeforeCreate),
				}},
				Check: resource.TestCheckResourceAttr("lastpass_secret.s", "group", "folder"),
			},
		},
	})
}

func TestSecretDataSource(t *testing.T) {
	server := lastpasstest.New(t, testUsername, testPassword)
	server.AddShare("Shared-Infra", false)
	id := server.Put(lastpass.Account{
		Share:    "Shared-Infra",
		Group:    "ssh",
		Name:     "bastion",
		URL:      "http://sn",
		Username: "",
		Notes:    "NoteType:SSH Key\nPassphrase:sésame\nPublic Key:ssh-ed25519 AAAA\nNotes:clé du bastion",
	})
	const address = "data.lastpass_secret.bastion"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProvider(t, server),
		Steps: []resource.TestStep{
			{
				Config: `data "lastpass_secret" "bastion" { id = "` + id + `" }`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(address, "name", "Shared-Infra/ssh/bastion"),
					resource.TestCheckResourceAttr(address, "fullname", "Shared-Infra/ssh/bastion"),
					resource.TestCheckResourceAttr(address, "group", "ssh"),
					resource.TestCheckResourceAttr(address, "url", "http://sn"),
					// A multi-line note is exposed with its final newline.
					resource.TestCheckResourceAttr(address, "note", "NoteType:SSH Key\nPassphrase:sésame\nPublic Key:ssh-ed25519 AAAA\nNotes:clé du bastion\n"),
					resource.TestCheckResourceAttr(address, "custom_fields.Passphrase", "sésame"),
					resource.TestCheckResourceAttr(address, "custom_fields.Public Key", "ssh-ed25519 AAAA"),
					resource.TestCheckResourceAttr(address, "custom_fields.Notes", "clé du bastion\n"),
				),
			},
			{
				Config:      `data "lastpass_secret" "missing" { id = "424242" }`,
				ExpectError: regexp.MustCompile(`LastPass entry not found`),
			},
			{
				Config:      `data "lastpass_secret" "bad" { id = "not-a-number" }`,
				ExpectError: regexp.MustCompile(`Not a valid LastPass ID`),
			},
		},
	})
}

func TestWritingToAnUnknownSharedFolderFails(t *testing.T) {
	server := lastpasstest.New(t, testUsername, testPassword)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProvider(t, server),
		Steps: []resource.TestStep{{
			Config:      `resource "lastpass_secret" "s" { name = "Shared-Missing/entry" }`,
			ExpectError: regexp.MustCompile(`shared folder Shared-Missing not found`),
		}},
	})
}
