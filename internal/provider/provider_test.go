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

func providerFactories(server *lastpasstest.Server) map[string]func() (tfprotov6.ProviderServer, error) {
	return map[string]func() (tfprotov6.ProviderServer, error){
		"lastpass": providerserver.NewProtocol6WithError(New("test", lastpass.WithBaseURL(server.URL))()),
	}
}

// testProvider gives the credentials through the environment, as CI does.
func testProvider(t *testing.T, server *lastpasstest.Server) map[string]func() (tfprotov6.ProviderServer, error) {
	t.Setenv("LASTPASS_USER", testUsername)
	t.Setenv("LASTPASS_PASSWORD", testPassword)
	return providerFactories(server)
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

// editElsewhere changes the entry called name the way another LastPass
// client would, or deletes it when edit is nil.
func editElsewhere(t *testing.T, server *lastpasstest.Server, name string, edit func(*lastpass.Account)) {
	t.Helper()
	account := stored(t, server, name)
	client, err := lastpass.Login(t.Context(), testUsername, testPassword, lastpass.WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	v, err := client.Vault(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if edit == nil {
		err = client.Delete(t.Context(), v, account)
	} else {
		edit(&account)
		err = client.Update(t.Context(), v, account)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func expectAction(address string, action plancheck.ResourceActionType) resource.ConfigPlanChecks {
	return resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(address, action)}}
}

var expectNoChange = resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}

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
					resource.TestCheckResourceAttrSet(address, "last_touch"),
					func(*terraform.State) error {
						account := stored(t, server, "aws_iam_key")
						if account.Share != "Shared-Infra" || account.Group != "tfstates" {
							t.Errorf("entry stored in %q / %q", account.Share, account.Group)
						}
						// The note is stored without its trailing newline.
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
				ConfigPlanChecks: expectNoChange,
			},
			{
				Config:           fmt.Sprintf(secretConfig, "rotated"),
				ConfigPlanChecks: expectAction(address, plancheck.ResourceActionUpdate),
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
			{
				ResourceName:  address,
				ImportState:   true,
				ImportStateId: "not-a-number",
				ExpectError:   regexp.MustCompile(`Not a valid LastPass ID`),
			},
		},
	})

	if remaining := server.Accounts(); len(remaining) != 0 {
		t.Errorf("destroy left %d entries on the server", len(remaining))
	}
}

func TestSecretResourceFollowsChangesMadeElsewhere(t *testing.T) {
	server := lastpasstest.New(t, testUsername, testPassword)
	const address = "lastpass_secret.site"
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
				// Someone edits the entry in LastPass: the next apply puts the password
				// back and leaves alone what the configuration does not set.
				PreConfig: func() {
					editElsewhere(t, server, "site", func(account *lastpass.Account) {
						account.Password = "changed by hand"
						account.Username = "set by hand"
					})
				},
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(address, "password", "from terraform"),
					resource.TestCheckResourceAttr(address, "username", "set by hand"),
				),
			},
			{
				// The entry is deleted in LastPass: Terraform recreates it.
				PreConfig:        func() { editElsewhere(t, server, "site", nil) },
				Config:           config,
				ConfigPlanChecks: expectAction(address, plancheck.ResourceActionCreate),
			},
		},
	})
}

// The provider's predecessor read "" as "not set". A configuration that
// passes "" (a variable's default, typically) must not blank the field.
func TestEmptyStringKeepsWhatTheEntryHolds(t *testing.T) {
	server := lastpasstest.New(t, testUsername, testPassword)
	const address = "lastpass_secret.site"
	const config = `
resource "lastpass_secret" "site" {
  name     = "site"
  username = ""
  password = ""
  url      = ""
  note     = ""
}
`
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProvider(t, server),
		Steps: []resource.TestStep{
			{Config: config},
			{
				PreConfig: func() {
					editElsewhere(t, server, "site", func(account *lastpass.Account) {
						account.Username, account.Password = "by hand", "by hand"
						account.URL, account.Notes = "https://example.com", "by\nhand"
					})
				},
				Config:           config,
				ConfigPlanChecks: expectNoChange,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(address, "username", "by hand"),
					resource.TestCheckResourceAttr(address, "password", "by hand"),
					resource.TestCheckResourceAttr(address, "url", "https://example.com"),
					resource.TestCheckResourceAttr(address, "note", "by\nhand\n"),
				),
			},
		},
	})
}

// LastPass accepts two entries with the same name; a configuration never
// means that. Creating over an existing entry takes it over.
func TestSecretResourceAdoptsAnExistingEntry(t *testing.T) {
	server := lastpasstest.New(t, testUsername, testPassword)
	existing := server.Put(lastpass.Account{Group: "sites", Name: "site", Username: "by hand", Password: "old", Notes: "kept"})
	const address = "lastpass_secret.site"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProvider(t, server),
		Steps: []resource.TestStep{{
			Config: `
resource "lastpass_secret" "site" {
  name     = "sites/site"
  password = "from terraform"
}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr(address, "id", existing),
				resource.TestCheckResourceAttr(address, "password", "from terraform"),
				resource.TestCheckResourceAttr(address, "username", "by hand"),
				resource.TestCheckResourceAttr(address, "note", "kept"),
				func(*terraform.State) error {
					if got := len(server.Accounts()); got != 1 {
						t.Errorf("%d entries on the server, want 1", got)
					}
					return nil
				},
			),
		}},
	})
}

func TestSecretResourceRenameReplacesTheEntry(t *testing.T) {
	server := lastpasstest.New(t, testUsername, testPassword)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProvider(t, server),
		Steps: []resource.TestStep{
			{Config: `resource "lastpass_secret" "s" { name = "folder/before" }`},
			{
				Config:           `resource "lastpass_secret" "s" { name = "folder/after" }`,
				ConfigPlanChecks: expectAction("lastpass_secret.s", plancheck.ResourceActionDestroyBeforeCreate),
				Check:            resource.TestCheckResourceAttr("lastpass_secret.s", "group", "folder"),
			},
		},
	})
}

func TestSecretResourceRejectsNamesLastPassWouldRewrite(t *testing.T) {
	server := lastpasstest.New(t, testUsername, testPassword)
	var steps []resource.TestStep
	for _, name := range []string{"/lead", "trail/", "Shared-Infra//double", "Shared-Infra/"} {
		steps = append(steps, resource.TestStep{
			Config:      fmt.Sprintf(`resource "lastpass_secret" "s" { name = %q }`, name),
			ExpectError: regexp.MustCompile(`Invalid entry name`),
		})
	}
	resource.UnitTest(t, resource.TestCase{ProtoV6ProviderFactories: testProvider(t, server), Steps: steps})

	if got := len(server.Requests("/login.php")); got != 0 {
		t.Errorf("an invalid name still reached LastPass (%d login requests)", got)
	}
}

func TestSecretResourceReportsARefusedWrite(t *testing.T) {
	server := lastpasstest.New(t, testUsername, testPassword)
	server.AddShare("Shared-ReadOnly", true)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProvider(t, server),
		Steps: []resource.TestStep{
			{
				Config:      `resource "lastpass_secret" "s" { name = "Shared-Missing/entry" }`,
				ExpectError: regexp.MustCompile(`shared folder Shared-Missing not found`),
			},
			{
				Config:      `resource "lastpass_secret" "s" { name = "Shared-ReadOnly/entry" }`,
				ExpectError: regexp.MustCompile(`shared folder Shared-ReadOnly is read-only`),
			},
		},
	})
}

func TestSecretDataSource(t *testing.T) {
	server := lastpasstest.New(t, testUsername, testPassword)
	server.AddShare("Shared-Infra", false)
	id := server.Put(lastpass.Account{
		Share: "Shared-Infra",
		Group: "ssh",
		Name:  "bastion",
		URL:   "http://sn",
		Notes: "NoteType:SSH Key\nPassphrase:sésame\nPublic Key:ssh-ed25519 AAAA\nNotes:clé du bastion",
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
					// A multi-line note is exposed with a final newline, and so is the
					// free-text field at its end.
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

func TestProviderCredentials(t *testing.T) {
	server := lastpasstest.New(t, testUsername, testPassword)
	id := server.Put(lastpass.Account{Name: "entry", Password: "pw"})
	t.Setenv("LASTPASS_USER", "")
	t.Setenv("LASTPASS_PASSWORD", "")
	data := `data "lastpass_secret" "entry" { id = "` + id + `" }`

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories(server),
		Steps: []resource.TestStep{
			{
				// Declared but unused: no credentials needed.
				Config: `output "unused" { value = "ok" }`,
			},
			{
				Config:      data,
				ExpectError: regexp.MustCompile(`LastPass credentials are missing`),
			},
			{
				Config: fmt.Sprintf(`provider "lastpass" {
  username = %q
  password = "stale"
}
`, testUsername) + data,
				ExpectError: regexp.MustCompile(`login refused \(unknownpassword\)`),
			},
			{
				Config: fmt.Sprintf(`provider "lastpass" {
  username = %q
  password = %q
}
`, testUsername, testPassword) + data,
				Check: resource.TestCheckResourceAttr("data.lastpass_secret.entry", "password", "pw"),
			},
		},
	})
}
