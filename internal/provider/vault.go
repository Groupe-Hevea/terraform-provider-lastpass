package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/Groupe-Hevea/terraform-provider-lastpass/internal/lastpass"
)

// vault is the provider's access to LastPass. It logs in on first use, so a
// configuration that declares the provider without using it needs no
// credentials, and keeps one decrypted snapshot of the vault: LastPass can
// only serve the vault whole, and a plan reads dozens of entries.
//
// Every operation holds the lock. Reads are served from the snapshot; writes
// go to LastPass one at a time and discard the snapshot, so the vault is
// downloaded once for all the reads of a run and once more after each write.
type vault struct {
	username string
	password string
	options  []lastpass.Option

	mu       sync.Mutex
	client   *lastpass.Client
	loginErr error
	snapshot *lastpass.Vault
}

// get returns the entry with the given ID, or nil if it does not exist.
func (v *vault) get(ctx context.Context, id string) (*lastpass.Account, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.lookup(ctx, id)
}

// create writes a new entry, or adopts the one that already has the same
// path: LastPass accepts namesakes, and a second entry is never what a
// configuration means. This also makes a creation safe to replay after a
// failure that left the entry behind. merge decides what the adopted entry
// becomes, given what it currently holds.
//
// The returned entry is non-nil as soon as LastPass holds it, even with an
// error: the caller must record its ID.
func (v *vault) create(ctx context.Context, account lastpass.Account, merge func(existing lastpass.Account) lastpass.Account) (created *lastpass.Account, adopted bool, err error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	snapshot, err := v.current(ctx)
	if err != nil {
		return nil, false, err
	}
	var namesakes []lastpass.Account
	for _, existing := range snapshot.Accounts {
		if fullname(&existing) == fullname(&account) {
			namesakes = append(namesakes, existing)
		}
	}
	switch len(namesakes) {
	case 0:
		err = v.write(ctx, func(ctx context.Context) error {
			account.ID, err = v.client.Add(ctx, snapshot, account)
			return err
		})
	case 1:
		account, adopted = merge(namesakes[0]), true
		err = v.write(ctx, func(ctx context.Context) error {
			return v.client.Update(ctx, snapshot, account)
		})
	default:
		ids := make([]string, len(namesakes))
		for i, namesake := range namesakes {
			ids[i] = namesake.ID
		}
		return nil, false, fmt.Errorf("%d entries are already named %q (IDs %s): delete the extra ones in LastPass, or import the right one",
			len(namesakes), fullname(&account), strings.Join(ids, ", "))
	}
	if err != nil {
		return nil, false, err
	}

	stored, err := v.lookup(ctx, account.ID)
	if err == nil && stored == nil {
		err = errors.New("LastPass accepted the entry " + account.ID + " but does not list it")
	}
	if err != nil {
		return &account, adopted, err
	}
	return stored, adopted, nil
}

// update overwrites the entry account.ID and returns it as LastPass stored it.
func (v *vault) update(ctx context.Context, account lastpass.Account) (*lastpass.Account, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	snapshot, err := v.current(ctx)
	if err != nil {
		return nil, err
	}
	existing, err := snapshot.Account(account.ID)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, lastpass.ErrAccountNotFound
	}
	// The master password reprompt is not managed by Terraform: keep it.
	account.Reprompt = existing.Reprompt
	err = v.write(ctx, func(ctx context.Context) error {
		return v.client.Update(ctx, snapshot, account)
	})
	if err != nil {
		return nil, err
	}
	stored, err := v.lookup(ctx, account.ID)
	if err == nil && stored == nil {
		err = errors.New("LastPass accepted the update of entry " + account.ID + " but no longer lists it")
	}
	return stored, err
}

// delete removes the entry; an entry that is already gone is not an error.
func (v *vault) delete(ctx context.Context, id string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	snapshot, err := v.current(ctx)
	if err != nil {
		return err
	}
	account, err := snapshot.Account(id)
	if err != nil || account == nil {
		return err
	}
	err = v.write(ctx, func(ctx context.Context) error {
		return v.client.Delete(ctx, snapshot, *account)
	})
	if !errors.Is(err, lastpass.ErrAccountNotFound) {
		return err
	}
	// LastPass answers "not found" with an empty reply, which could hide
	// another refusal: only the vault tells whether the entry is gone.
	remaining, err := v.lookup(ctx, id)
	if err != nil {
		return err
	}
	if remaining != nil {
		return errors.New("LastPass did not delete the entry " + id + " and gave no reason")
	}
	return nil
}

func (v *vault) lookup(ctx context.Context, id string) (*lastpass.Account, error) {
	snapshot, err := v.current(ctx)
	if err != nil {
		return nil, err
	}
	return snapshot.Account(id)
}

// write runs one modification and discards the snapshot, whatever the
// outcome: after a failed write the state of the vault is unknown.
//
// The modification is detached from the caller's cancellation. Terraform
// cancels in-flight requests when it is interrupted; a write cut at that
// point may or may not have reached LastPass, and letting it finish is what
// keeps the state file truthful.
func (v *vault) write(ctx context.Context, modify func(context.Context) error) error {
	v.snapshot = nil
	return modify(context.WithoutCancel(ctx))
}

// current returns the snapshot, logging in and downloading the vault as
// needed. A refused login is remembered: every resource of a run would
// otherwise retry it, and LastPass locks accounts out.
func (v *vault) current(ctx context.Context) (*lastpass.Vault, error) {
	if v.loginErr != nil {
		return nil, v.loginErr
	}
	if v.client == nil {
		if v.username == "" || v.password == "" {
			return nil, errors.New("LastPass credentials are missing: set the provider's username and password, or the LASTPASS_USER and LASTPASS_PASSWORD environment variables")
		}
		client, err := lastpass.Login(ctx, v.username, v.password, v.options...)
		if err != nil {
			if ctx.Err() == nil {
				v.loginErr = err
			}
			return nil, err
		}
		v.client = client
	}
	if v.snapshot == nil {
		snapshot, err := v.client.Vault(ctx)
		if err != nil {
			return nil, err
		}
		v.snapshot = snapshot
	}
	return v.snapshot, nil
}
