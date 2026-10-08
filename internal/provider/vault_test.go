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

func TestVaultIsDownloadedOncePerRun(t *testing.T) {
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
	// One wrong guess of the iteration count, then the real login.
	if got := len(server.Requests("/login.php")); got != 2 {
		t.Errorf("got %d login requests, want 2", got)
	}
}

func TestVaultSeesItsOwnWrites(t *testing.T) {
	ctx := context.Background()
	server := lastpasstest.New(t, testUsername, testPassword)
	v := newTestVault(server)

	created, err := v.create(ctx, lastpass.Account{Name: "entry", Password: "one"})
	if err != nil {
		t.Fatalf("create: %v", err)
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
			if _, err := v.create(ctx, lastpass.Account{Name: fmt.Sprintf("entry-%d", i)}); err != nil {
				t.Errorf("create %d: %v", i, err)
			}
		}()
	}
	wg.Wait()

	if got := len(server.Accounts()); got != writers {
		t.Errorf("%d entries stored, want %d", got, writers)
	}
}

func TestMissingCredentialsFailOnlyWhenTheVaultIsUsed(t *testing.T) {
	v := &vault{}
	_, err := v.get(context.Background(), "1")
	if err == nil || !strings.Contains(err.Error(), "LASTPASS_USER") {
		t.Errorf("got %v, want an error naming the environment variables", err)
	}
}
