package provider

import (
	"context"
	"errors"
	"sync"

	"github.com/Groupe-Hevea/terraform-provider-lastpass/internal/lastpass"
)

// vault is the provider's access to LastPass. It logs in on first use, so a
// configuration that declares the provider without using it needs no
// credentials, and keeps one decrypted snapshot of the vault: LastPass can
// only serve the vault whole, and a plan reads dozens of entries.
//
// Every operation holds the lock. Reads are served from the snapshot; writes
// go to LastPass one at a time and discard the snapshot.
type vault struct {
	username string
	password string
	options  []lastpass.Option

	mu       sync.Mutex
	client   *lastpass.Client
	snapshot *lastpass.Vault
}

// get returns the entry with the given ID, or nil if it does not exist.
func (v *vault) get(ctx context.Context, id string) (*lastpass.Account, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.lookup(ctx, id)
}

// create adds the entry and returns it as LastPass stored it.
func (v *vault) create(ctx context.Context, account lastpass.Account) (*lastpass.Account, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	err := v.write(ctx, func(client *lastpass.Client, snapshot *lastpass.Vault) error {
		return client.Add(ctx, snapshot, &account)
	})
	if err != nil {
		return nil, err
	}
	return v.lookupWritten(ctx, account.ID)
}

// update overwrites the entry account.ID and returns it as LastPass stored it.
func (v *vault) update(ctx context.Context, account lastpass.Account) (*lastpass.Account, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	err := v.write(ctx, func(client *lastpass.Client, snapshot *lastpass.Vault) error {
		return client.Update(ctx, snapshot, &account)
	})
	if err != nil {
		return nil, err
	}
	return v.lookupWritten(ctx, account.ID)
}

// delete removes the entry; an entry that is already gone is not an error.
func (v *vault) delete(ctx context.Context, id string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	account, err := v.lookup(ctx, id)
	if err != nil || account == nil {
		return err
	}
	err = v.write(ctx, func(client *lastpass.Client, snapshot *lastpass.Vault) error {
		return client.Delete(ctx, snapshot, account)
	})
	if errors.Is(err, lastpass.ErrAccountNotFound) {
		return nil
	}
	return err
}

func (v *vault) lookup(ctx context.Context, id string) (*lastpass.Account, error) {
	snapshot, err := v.current(ctx)
	if err != nil {
		return nil, err
	}
	return snapshot.Account(id), nil
}

func (v *vault) lookupWritten(ctx context.Context, id string) (*lastpass.Account, error) {
	account, err := v.lookup(ctx, id)
	if err != nil {
		return nil, err
	}
	if account == nil {
		return nil, errors.New("LastPass accepted the entry " + id + " but does not list it")
	}
	return account, nil
}

// write runs one modification and discards the snapshot, whatever the
// outcome: after a failed write the state of the vault is unknown.
func (v *vault) write(ctx context.Context, modify func(*lastpass.Client, *lastpass.Vault) error) error {
	snapshot, err := v.current(ctx)
	if err != nil {
		return err
	}
	v.snapshot = nil
	return modify(v.client, snapshot)
}

func (v *vault) current(ctx context.Context) (*lastpass.Vault, error) {
	if v.client == nil {
		if v.username == "" || v.password == "" {
			return nil, errors.New("LastPass provider not configured. Please provide username and password (eg: environment variables LASTPASS_USER and LASTPASS_PASSWORD)")
		}
		client, err := lastpass.Login(ctx, v.username, v.password, v.options...)
		if err != nil {
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
