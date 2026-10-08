package lastpass_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Groupe-Hevea/terraform-provider-lastpass/internal/lastpass"
	"github.com/Groupe-Hevea/terraform-provider-lastpass/internal/lastpass/lastpasstest"
)

const (
	username = "Service.Account@example.com"
	password = "correct horse battery staple"
	shared   = "Shared-Infra"
)

func login(t *testing.T, server *lastpasstest.Server) *lastpass.Client {
	t.Helper()
	client, err := lastpass.Login(context.Background(), username, password, lastpass.WithBaseURL(server.URL))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	return client
}

func vault(t *testing.T, client *lastpass.Client) *lastpass.Vault {
	t.Helper()
	v, err := client.Vault(context.Background())
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	return v
}

func TestLoginFollowsTheIterationCountOfTheAccount(t *testing.T) {
	server := lastpasstest.New(t, username, password)
	login(t, server)

	attempts := server.Requests("/login.php")
	if len(attempts) != 2 {
		t.Fatalf("got %d login attempts, want a wrong guess then the hinted count", len(attempts))
	}
	if got := attempts[1].Form.Get("iterations"); got != "5000" {
		t.Errorf("second attempt used %s iterations, want 5000", got)
	}
	if got := attempts[1].Form.Get("username"); got != strings.ToLower(username) {
		t.Errorf("username sent as %q, want it lowercased", got)
	}
}

func TestLoginRefused(t *testing.T) {
	server := lastpasstest.New(t, username, password)
	_, err := lastpass.Login(context.Background(), username, "wrong", lastpass.WithBaseURL(server.URL))

	var authErr *lastpass.AuthenticationError
	if !errors.As(err, &authErr) {
		t.Fatalf("got %v, want an AuthenticationError", err)
	}
	if authErr.Cause != "unknownpassword" {
		t.Errorf("cause = %q, want unknownpassword", authErr.Cause)
	}
}

func TestVaultListsPersonalAndSharedEntries(t *testing.T) {
	server := lastpasstest.New(t, username, password)
	server.AddShare(shared, false)
	personal := server.Put(lastpass.Account{Name: "personal", Username: "me", Password: "pw", URL: "https://example.com", Notes: "été\nhiver"})
	inShare := server.Put(lastpass.Account{Share: shared, Group: "aws/keys", Name: "key", Password: "secret"})
	server.Put(lastpass.Account{Share: shared, Group: "aws", URL: "http://group"})
	note := server.Put(lastpass.Account{Share: shared, Name: "note", URL: "http://sn", Notes: "NoteType:Server\nHostname:h"})

	v := vault(t, login(t, server))

	if len(v.Accounts) != 3 {
		t.Fatalf("got %d entries, want 3 (the folder placeholder is skipped)", len(v.Accounts))
	}
	if got := v.Account(personal); got == nil || got.Share != "" || got.Username != "me" || got.URL != "https://example.com" || got.Notes != "été\nhiver" {
		t.Errorf("personal entry = %+v", got)
	}
	if got := v.Account(inShare); got == nil || got.Share != shared || got.Group != "aws/keys" || got.Name != "key" || got.Password != "secret" {
		t.Errorf("shared entry = %+v", got)
	}
	if got := v.Account(note); got == nil || got.URL != "http://sn" || got.Notes != "NoteType:Server\nHostname:h" {
		t.Errorf("secure note = %+v", got)
	}
	if v.Account("424242") != nil {
		t.Error("an unknown ID returned an entry")
	}
}

func TestVaultReadsHexEncodedURLs(t *testing.T) {
	server := lastpasstest.New(t, username, password)
	server.URLEncryption = false
	id := server.Put(lastpass.Account{Name: "old", URL: "https://example.com"})

	if got := vault(t, login(t, server)).Account(id); got == nil || got.URL != "https://example.com" {
		t.Errorf("entry = %+v", got)
	}
}

func TestAddUpdateDelete(t *testing.T) {
	ctx := context.Background()
	server := lastpasstest.New(t, username, password)
	server.AddShare(shared, false)
	client := login(t, server)

	account := &lastpass.Account{Share: shared, Group: "tfstates", Name: "key", Username: "AKIA", Password: "s3cr3t", URL: "https://aws.example", Notes: "line one\nline two"}
	if err := client.Add(ctx, vault(t, client), account); err != nil {
		t.Fatalf("add: %v", err)
	}
	if account.ID == "" || account.ID == "0" {
		t.Fatalf("add did not set the ID: %q", account.ID)
	}
	stored := vault(t, client).Account(account.ID)
	if stored == nil || stored.Share != shared || stored.Group != "tfstates" || stored.Name != "key" || stored.Username != "AKIA" ||
		stored.Password != "s3cr3t" || stored.URL != "https://aws.example" || stored.Notes != "line one\nline two" {
		t.Fatalf("stored entry = %+v", stored)
	}

	account.Password = "rotated"
	if err := client.Update(ctx, vault(t, client), account); err != nil {
		t.Fatalf("update: %v", err)
	}
	updated := vault(t, client).Account(account.ID)
	if updated.Password != "rotated" || updated.LastModifiedGMT == stored.LastModifiedGMT {
		t.Errorf("updated entry = %+v", updated)
	}

	if err := client.Delete(ctx, vault(t, client), account); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if vault(t, client).Account(account.ID) != nil {
		t.Error("entry still present after delete")
	}

	if err := client.Update(ctx, vault(t, client), account); !errors.Is(err, lastpass.ErrAccountNotFound) {
		t.Errorf("update of a deleted entry: got %v, want ErrAccountNotFound", err)
	}
	if err := client.Delete(ctx, vault(t, client), account); !errors.Is(err, lastpass.ErrAccountNotFound) {
		t.Errorf("delete of a deleted entry: got %v, want ErrAccountNotFound", err)
	}
}

// The official client encrypts the URL only when the account has the feature
// flag, and never for a secure note: entries written otherwise are unreadable
// to it.
func TestURLEncodingFollowsTheAccountFlag(t *testing.T) {
	ctx := context.Background()
	for _, test := range []struct {
		name          string
		urlEncryption bool
		url           string
		wantEncrypted bool
	}{
		{"flag on", true, "https://example.com", true},
		{"flag on, secure note", true, "http://sn", false},
		{"flag off", false, "https://example.com", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := lastpasstest.New(t, username, password)
			server.URLEncryption = test.urlEncryption
			client := login(t, server)

			account := &lastpass.Account{Name: "entry", URL: test.url}
			if err := client.Add(ctx, vault(t, client), account); err != nil {
				t.Fatalf("add: %v", err)
			}
			writes := server.Requests("/show_website.php")
			sent := writes[len(writes)-1].Form.Get("url")
			if got := strings.HasPrefix(sent, "!"); got != test.wantEncrypted {
				t.Errorf("url sent as %q, want encrypted = %t", sent, test.wantEncrypted)
			}
			if got := vault(t, client).Account(account.ID); got == nil || got.URL != test.url {
				t.Errorf("stored entry = %+v", got)
			}
		})
	}
}

func TestWritesToSharedFoldersAreChecked(t *testing.T) {
	ctx := context.Background()
	server := lastpasstest.New(t, username, password)
	server.AddShare("Shared-ReadOnly", true)
	client := login(t, server)
	v := vault(t, client)

	if err := client.Add(ctx, v, &lastpass.Account{Share: "Shared-ReadOnly", Name: "x"}); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Errorf("add to a read-only folder: got %v", err)
	}
	if err := client.Add(ctx, v, &lastpass.Account{Share: "Shared-Missing", Name: "x"}); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("add to an unknown folder: got %v", err)
	}
	if len(server.Requests("/show_website.php")) != 0 {
		t.Error("a refused write still reached LastPass")
	}
}
