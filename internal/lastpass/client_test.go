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

// entry returns the entry id, which must exist and be readable.
func entry(t *testing.T, v *lastpass.Vault, id string) lastpass.Account {
	t.Helper()
	account, err := v.Account(id)
	if err != nil || account == nil {
		t.Fatalf("entry %s: %v, %v", id, account, err)
	}
	return *account
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
	if err == nil || !strings.Contains(err.Error(), "login refused (unknownpassword): Invalid Password!") {
		t.Errorf("got %v, want the refusal and its cause", err)
	}
}

func TestVaultListsPersonalAndSharedEntries(t *testing.T) {
	server := lastpasstest.New(t, username, password)
	server.AddShare(shared, false)
	personal := server.Put(lastpass.Account{Name: "personal", Username: "me", Password: "pw", URL: "https://example.com", Notes: "été\nhiver", Reprompt: true})
	inShare := server.Put(lastpass.Account{Share: shared, Group: "aws/keys", Name: "key", Password: "secret"})
	server.Put(lastpass.Account{Share: shared, Group: "aws", URL: "http://group"})
	note := server.Put(lastpass.Account{Share: shared, Name: "note", URL: "http://sn", Notes: "NoteType:Server\nHostname:h"})

	v := vault(t, login(t, server))

	if len(v.Accounts) != 3 {
		t.Fatalf("got %d entries, want 3 (the folder placeholder is skipped)", len(v.Accounts))
	}
	if got := entry(t, v, personal); got.Share != "" || got.Username != "me" || got.Password != "pw" || got.URL != "https://example.com" ||
		got.Notes != "été\nhiver" || !got.Reprompt || got.LastTouch == "" || got.LastModifiedGMT == "" {
		t.Errorf("personal entry = %+v", got)
	}
	if got := entry(t, v, inShare); got.Share != shared || got.Group != "aws/keys" || got.Name != "key" || got.Password != "secret" || got.Reprompt {
		t.Errorf("shared entry = %+v", got)
	}
	if got := entry(t, v, note); got.URL != "http://sn" || got.Notes != "NoteType:Server\nHostname:h" {
		t.Errorf("secure note = %+v", got)
	}
	if account, err := v.Account("424242"); account != nil || err != nil {
		t.Errorf("unknown ID: got %v, %v", account, err)
	}
}

// A shared folder nobody opened yet needs the account's private key, which
// LastPass serves in one of two serializations.
func TestVaultOpensSharedFoldersWithThePrivateKey(t *testing.T) {
	for name, legacy := range map[string]bool{"current serialization": false, "original serialization": true} {
		t.Run(name, func(t *testing.T) {
			server := lastpasstest.New(t, username, password)
			server.LegacyPrivateKey = legacy
			server.AddUnopenedShare(shared)
			id := server.Put(lastpass.Account{Share: shared, Name: "key", Password: "secret"})

			if got := entry(t, vault(t, login(t, server)), id); got.Share != shared || got.Password != "secret" {
				t.Errorf("entry = %+v", got)
			}
		})
	}
}

// One broken entry must not take the whole vault down: it fails when asked for.
func TestUnreadableEntryDoesNotBreakTheOthers(t *testing.T) {
	server := lastpasstest.New(t, username, password)
	good := server.Put(lastpass.Account{Name: "good", Password: "pw"})
	broken := server.Put(lastpass.Account{Name: "broken", Password: "pw"})
	server.Corrupt(broken)

	v := vault(t, login(t, server))

	if got := entry(t, v, good); got.Password != "pw" {
		t.Errorf("good entry = %+v", got)
	}
	if account, err := v.Account(broken); account != nil || err == nil || !strings.Contains(err.Error(), "cannot be read") {
		t.Errorf("broken entry: got %v, %v, want an error", account, err)
	}
}

// A vault cut short would otherwise read as a vault with entries deleted.
func TestTruncatedVaultIsAnError(t *testing.T) {
	server := lastpasstest.New(t, username, password)
	server.Put(lastpass.Account{Name: "entry"})
	server.Truncated = true

	if _, err := login(t, server).Vault(context.Background()); err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Errorf("got %v, want a truncation error", err)
	}
}

func TestAddUpdateDelete(t *testing.T) {
	ctx := context.Background()
	server := lastpasstest.New(t, username, password)
	server.AddShare(shared, false)
	client := login(t, server)

	account := lastpass.Account{Share: shared, Group: "tfstates", Name: "key", Username: "AKIA", Password: "s3cr3t", URL: "https://aws.example", Notes: "line one\nline two"}
	id, err := client.Add(ctx, vault(t, client), account)
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	stored := entry(t, vault(t, client), id)
	account.ID, account.LastTouch, account.LastModifiedGMT = id, stored.LastTouch, stored.LastModifiedGMT
	if stored != account {
		t.Fatalf("stored entry = %+v, want %+v", stored, account)
	}

	account.Password, account.Reprompt = "rotated", true
	if err := client.Update(ctx, vault(t, client), account); err != nil {
		t.Fatalf("update: %v", err)
	}
	updated := entry(t, vault(t, client), id)
	if updated.LastModifiedGMT == stored.LastModifiedGMT {
		t.Error("update did not change the modification time")
	}
	account.LastModifiedGMT = updated.LastModifiedGMT
	if updated != account {
		t.Errorf("updated entry = %+v, want %+v", updated, account)
	}

	if err := client.Delete(ctx, vault(t, client), account); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if got, err := vault(t, client).Account(id); got != nil || err != nil {
		t.Errorf("after delete: got %v, %v", got, err)
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

			id, err := client.Add(ctx, vault(t, client), lastpass.Account{Name: "entry", URL: test.url})
			if err != nil {
				t.Fatalf("add: %v", err)
			}
			writes := server.Requests("/show_website.php")
			sent := writes[len(writes)-1].Form.Get("url")
			if got := strings.HasPrefix(sent, "!"); got != test.wantEncrypted {
				t.Errorf("url sent as %q, want encrypted = %t", sent, test.wantEncrypted)
			}
			if got := entry(t, vault(t, client), id); got.URL != test.url {
				t.Errorf("stored entry = %+v", got)
			}
		})
	}
}

func TestWritesToSharedFoldersAreChecked(t *testing.T) {
	ctx := context.Background()
	server := lastpasstest.New(t, username, password)
	server.AddShare("Shared-ReadOnly", true)
	existing := server.Put(lastpass.Account{Share: "Shared-ReadOnly", Name: "existing"})
	client := login(t, server)
	v := vault(t, client)
	inReadOnly := lastpass.Account{ID: existing, Share: "Shared-ReadOnly", Name: "existing"}

	if _, err := client.Add(ctx, v, lastpass.Account{Share: "Shared-ReadOnly", Name: "x"}); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Errorf("add to a read-only folder: got %v", err)
	}
	if err := client.Update(ctx, v, inReadOnly); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Errorf("update in a read-only folder: got %v", err)
	}
	if err := client.Delete(ctx, v, inReadOnly); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Errorf("delete in a read-only folder: got %v", err)
	}
	if _, err := client.Add(ctx, v, lastpass.Account{Share: "Shared-Missing", Name: "x"}); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("add to an unknown folder: got %v", err)
	}
	if len(server.Requests("/show_website.php")) != 0 {
		t.Error("a refused write still reached LastPass")
	}
}
