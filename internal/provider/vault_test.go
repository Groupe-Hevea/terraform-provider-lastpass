package provider

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/Groupe-Hevea/terraform-provider-lastpass/internal/lastpass"
	"github.com/Groupe-Hevea/terraform-provider-lastpass/internal/lastpass/lastpasstest"
)

const (
	testUsername = "terraform@example.com"
	testPassword = "master password"
)

func newTestVault(server *lastpasstest.Server) *vault {
	return &vault{
		username: testUsername,
		password: testPassword,
		options:  []lastpass.Option{lastpass.WithBaseURL(server.URL)},
	}
}

// overwrite is the merge of a creation that ignores what an adopted entry held.
func overwrite(desired lastpass.Account) func(lastpass.Account) lastpass.Account {
	return func(existing lastpass.Account) lastpass.Account {
		desired.ID = existing.ID
		return desired
	}
}

func TestVaultIsDownloadedOnceForAllReads(t *testing.T) {
	ctx := context.Background()
	server := lastpasstest.New(t, testUsername, testPassword)
	first := server.Put(lastpass.Account{Name: "first"})
	second := server.Put(lastpass.Account{Name: "second"})
	v := newTestVault(server)

	var wg sync.WaitGroup
	for range 10 {
		for _, id := range []string{first, second} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if account, err := v.get(ctx, id); err != nil || account == nil {
					t.Errorf("get(%s) = %v, %v", id, account, err)
				}
			}()
		}
	}
	wg.Wait()

	if got := len(server.Requests("/getaccts.php")); got != 1 {
		t.Errorf("the vault was downloaded %d times for 20 reads, want 1", got)
	}
}

func TestVaultSeesItsOwnWrites(t *testing.T) {
	ctx := context.Background()
	server := lastpasstest.New(t, testUsername, testPassword)
	v := newTestVault(server)

	desired := lastpass.Account{Name: "entry", Password: "one"}
	created, adopted, err := v.create(ctx, desired, overwrite(desired))
	if err != nil || adopted {
		t.Fatalf("create: adopted=%t, err=%v", adopted, err)
	}
	if created.ID == "" || created.LastModifiedGMT == "" {
		t.Fatalf("created entry lacks what LastPass assigns: %+v", created)
	}

	changed := *created
	changed.Password = "two"
	updated, err := v.update(ctx, changed)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Password != "two" || updated.LastModifiedGMT == created.LastModifiedGMT {
		t.Errorf("updated entry = %+v", updated)
	}

	if err := v.delete(ctx, created.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if account, err := v.get(ctx, created.ID); err != nil || account != nil {
		t.Errorf("after delete, get = %v, %v", account, err)
	}
	if err := v.delete(ctx, created.ID); err != nil {
		t.Errorf("deleting an entry that is already gone: %v", err)
	}
}

// Terraform applies resources in parallel. Writes must reach LastPass one at
// a time, and none may be lost.
func TestConcurrentWritesAllLand(t *testing.T) {
	ctx := context.Background()
	server := lastpasstest.New(t, testUsername, testPassword)
	v := newTestVault(server)

	const writers = 12
	var wg sync.WaitGroup
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			desired := lastpass.Account{Name: fmt.Sprintf("entry-%d", i)}
			if _, _, err := v.create(ctx, desired, overwrite(desired)); err != nil {
				t.Errorf("create %d: %v", i, err)
			}
		}()
	}
	wg.Wait()

	if got := len(server.Accounts()); got != writers {
		t.Errorf("%d entries stored, want %d", got, writers)
	}
}

func TestCreateAdoptsTheEntryWithTheSameName(t *testing.T) {
	ctx := context.Background()
	server := lastpasstest.New(t, testUsername, testPassword)
	server.AddShare("Shared-Infra", false)
	existing := server.Put(lastpass.Account{Share: "Shared-Infra", Group: "keys", Name: "key", Username: "by hand", Password: "old"})
	server.Put(lastpass.Account{Group: "keys", Name: "key"}) // same folder and name, but in the personal vault
	v := newTestVault(server)

	desired := lastpass.Account{Share: "Shared-Infra", Group: "keys", Name: "key", Password: "new"}
	created, adopted, err := v.create(ctx, desired, func(existing lastpass.Account) lastpass.Account {
		merged := desired
		merged.ID, merged.Username = existing.ID, existing.Username
		return merged
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !adopted || created.ID != existing || created.Password != "new" || created.Username != "by hand" {
		t.Errorf("adopted=%t, entry=%+v, want the existing entry %s updated", adopted, created, existing)
	}
	if got := len(server.Accounts()); got != 2 {
		t.Errorf("%d entries on the server, want the 2 that were there", got)
	}
}

func TestCreateDoesNotChooseBetweenNamesakes(t *testing.T) {
	server := lastpasstest.New(t, testUsername, testPassword)
	first := server.Put(lastpass.Account{Name: "twin"})
	second := server.Put(lastpass.Account{Name: "twin"})
	v := newTestVault(server)

	desired := lastpass.Account{Name: "twin"}
	_, _, err := v.create(context.Background(), desired, overwrite(desired))
	if err == nil || !strings.Contains(err.Error(), first) || !strings.Contains(err.Error(), second) {
		t.Errorf("got %v, want an error naming both IDs", err)
	}
	if got := len(server.Requests("/show_website.php")); got != 0 {
		t.Errorf("%d writes were sent", got)
	}
}

// LastPass creates the entry but the reply never arrives: Terraform sees a
// failure and the user runs apply again. That must not leave two entries.
func TestCreateIsSafeToReplayAfterALostReply(t *testing.T) {
	ctx := context.Background()
	server := lastpasstest.New(t, testUsername, testPassword)
	v := newTestVault(server)
	desired := lastpass.Account{Name: "entry", Password: "pw"}

	server.FailNext("/show_website.php", lastpasstest.LoseReply)
	if created, _, err := v.create(ctx, desired, overwrite(desired)); err == nil || created != nil {
		t.Fatalf("first attempt: got %v, %v, want a failure", created, err)
	}

	created, adopted, err := v.create(ctx, desired, overwrite(desired))
	if err != nil || !adopted {
		t.Fatalf("replay: adopted=%t, err=%v", adopted, err)
	}
	if accounts := server.Accounts(); len(accounts) != 1 || accounts[0].ID != created.ID {
		t.Errorf("entries on the server: %+v, want only %s", accounts, created.ID)
	}
}

// Once LastPass holds the entry, its ID must reach the caller even if the
// vault cannot be downloaded again to read it back.
func TestCreateReturnsTheIDWhenTheVaultCannotBeReadBack(t *testing.T) {
	ctx := context.Background()
	server := lastpasstest.New(t, testUsername, testPassword)
	v := newTestVault(server)
	if _, err := v.get(ctx, "1"); err != nil { // first download of the vault
		t.Fatal(err)
	}

	server.FailNext("/getaccts.php", lastpasstest.Refuse)
	desired := lastpass.Account{Name: "entry", Password: "pw"}
	created, _, err := v.create(ctx, desired, overwrite(desired))
	if err == nil {
		t.Fatal("the failed download went unreported")
	}
	accounts := server.Accounts()
	if len(accounts) != 1 || created == nil || created.ID != accounts[0].ID {
		t.Errorf("created = %+v, entries on the server = %+v", created, accounts)
	}
}

func TestUpdateKeepsTheMasterPasswordReprompt(t *testing.T) {
	ctx := context.Background()
	server := lastpasstest.New(t, testUsername, testPassword)
	id := server.Put(lastpass.Account{Name: "protected", Password: "old", Reprompt: true})
	v := newTestVault(server)

	updated, err := v.update(ctx, lastpass.Account{ID: id, Name: "protected", Password: "new"})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Password != "new" || !updated.Reprompt {
		t.Errorf("updated entry = %+v, want the reprompt still on", updated)
	}
}

// LastPass answers a write on an unknown entry with an empty reply, and
// nothing guarantees that is the only case: a delete counts as done only if
// the entry is really gone.
func TestDeleteChecksThatTheEntryIsGone(t *testing.T) {
	ctx := context.Background()
	server := lastpasstest.New(t, testUsername, testPassword)
	id := server.Put(lastpass.Account{Name: "stubborn"})
	v := newTestVault(server)

	server.FailNext("/show_website.php", lastpasstest.Ignore)
	if err := v.delete(ctx, id); err == nil || !strings.Contains(err.Error(), "did not delete") {
		t.Errorf("got %v, want an error", err)
	}
	if len(server.Accounts()) != 1 {
		t.Error("the entry is gone although the delete was ignored")
	}
}

func TestUnreadableEntryFailsOnlyWhenAskedFor(t *testing.T) {
	ctx := context.Background()
	server := lastpasstest.New(t, testUsername, testPassword)
	good := server.Put(lastpass.Account{Name: "good"})
	broken := server.Put(lastpass.Account{Name: "broken"})
	server.Corrupt(broken)
	v := newTestVault(server)

	if account, err := v.get(ctx, good); err != nil || account == nil {
		t.Errorf("good entry: %v, %v", account, err)
	}
	if _, err := v.get(ctx, broken); err == nil {
		t.Error("the unreadable entry was returned without error")
	}
}

// A stale password must not be tried once per resource: LastPass locks
// accounts out.
func TestRefusedLoginIsNotRetried(t *testing.T) {
	ctx := context.Background()
	server := lastpasstest.New(t, testUsername, testPassword)
	v := newTestVault(server)
	v.password = "stale"

	for range 5 {
		if _, err := v.get(ctx, "1"); err == nil || !strings.Contains(err.Error(), "login refused") {
			t.Fatalf("got %v, want a refused login", err)
		}
	}
	// One wrong guess of the iteration count, then the refused login.
	if got := len(server.Requests("/login.php")); got != 2 {
		t.Errorf("got %d login requests for 5 reads, want 2", got)
	}
}

func TestMissingCredentialsAreReportedOnUse(t *testing.T) {
	v := &vault{}
	_, err := v.get(context.Background(), "1")
	if err == nil || !strings.Contains(err.Error(), "LASTPASS_USER") {
		t.Errorf("got %v, want an error naming the environment variables", err)
	}
}
