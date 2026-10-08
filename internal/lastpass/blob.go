package lastpass

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

// Account is one vault entry.
type Account struct {
	ID       string
	Name     string
	Username string
	Password string
	URL      string
	// Group is the folder of the entry inside its shared folder (or inside the
	// personal vault), with "/" between nested folders.
	Group string
	// Share is the name of the shared folder holding the entry, empty for the
	// personal vault.
	Share string
	Notes string
	// Timestamps in seconds, set by LastPass.
	LastModifiedGMT string
	LastTouch       string
}

// Vault is a decrypted snapshot of the vault.
type Vault struct {
	Accounts []Account
	shares   []share
}

// Account returns the entry with the given ID, or nil.
func (v *Vault) Account(id string) *Account {
	for i := range v.Accounts {
		if v.Accounts[i].ID == id {
			return &v.Accounts[i]
		}
	}
	return nil
}

type share struct {
	id       string
	name     string
	key      []byte
	readOnly bool
}

// URLs that are markers rather than addresses: LastPass creates a
// placeholder entry per folder, and stores secure notes as entries.
const (
	urlFolderPlaceholder = "http://group"
	urlSecureNote        = "http://sn"
)

// Positions of the fields this client reads in an ACCT chunk, see
// https://github.com/lastpass/lastpass-cli/blob/master/blob.c (account_parse).
const (
	acctID              = 0
	acctName            = 1
	acctGroup           = 2
	acctURL             = 3
	acctNote            = 4
	acctUsername        = 7
	acctPassword        = 8
	acctLastTouch       = 12
	acctLastModifiedGMT = 31
)

// Positions of the fields in a SHAR chunk (share_parse in the same file).
const (
	sharID           = 0
	sharKeyRSA       = 1
	sharName         = 2
	sharReadOnly     = 3
	sharKeyAES       = 5
	sharMinimumItems = 6
)

// parseVault decrypts the blob returned by getaccts.php. The blob is a list of
// chunks; entries following a SHAR chunk belong to that shared folder and are
// encrypted with its sharing key.
func parseVault(blob, vaultKey []byte, privateKey *rsa.PrivateKey) (*Vault, error) {
	vault := &Vault{}
	key := vaultKey
	shareName := ""
	complete := false

	for len(blob) > 0 {
		if len(blob) < 4 {
			return nil, errors.New("vault is truncated")
		}
		id := string(blob[:4])
		payload, rest, err := readItem(blob[4:])
		if err != nil {
			return nil, err
		}
		blob = rest

		switch id {
		case "ACCT":
			account, err := parseAccount(payload, key)
			if err != nil {
				return nil, err
			}
			if account.URL == urlFolderPlaceholder {
				continue
			}
			account.Share = shareName
			vault.Accounts = append(vault.Accounts, *account)

		case "SHAR":
			s, err := parseShare(payload, vaultKey, privateKey)
			if err != nil {
				return nil, err
			}
			vault.shares = append(vault.shares, s)
			key, shareName = s.key, s.name

		case "ENDM":
			complete = string(payload) == "OK"
		}
	}
	if !complete {
		return nil, errors.New("vault is truncated")
	}
	return vault, nil
}

func parseAccount(payload, key []byte) (*Account, error) {
	items, err := readItems(payload)
	if err != nil {
		return nil, err
	}
	if len(items) <= acctLastModifiedGMT {
		return nil, fmt.Errorf("vault entry has %d fields, expected more than %d", len(items), acctLastModifiedGMT)
	}
	account := &Account{
		ID:              string(items[acctID]),
		LastTouch:       string(items[acctLastTouch]),
		LastModifiedGMT: string(items[acctLastModifiedGMT]),
	}
	for _, field := range []struct {
		dst *string
		pos int
	}{
		{&account.Name, acctName},
		{&account.Group, acctGroup},
		{&account.Notes, acctNote},
		{&account.Username, acctUsername},
		{&account.Password, acctPassword},
	} {
		if *field.dst, err = DecryptField(items[field.pos], key); err != nil {
			return nil, fmt.Errorf("vault entry %s: %w", account.ID, err)
		}
	}
	if account.URL, err = decodeURL(items[acctURL], key); err != nil {
		return nil, fmt.Errorf("vault entry %s: %w", account.ID, err)
	}
	return account, nil
}

// decodeURL reads the url field: hex-encoded historically, encrypted like the
// other fields on accounts where LastPass enabled URL encryption. Both forms
// coexist in a vault (secure notes and folder placeholders stay hex-encoded).
func decodeURL(data, key []byte) (string, error) {
	if bytes.HasPrefix(data, []byte("!")) {
		return DecryptField(data, key)
	}
	decoded, err := hex.DecodeString(string(data))
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

func parseShare(payload, vaultKey []byte, privateKey *rsa.PrivateKey) (share, error) {
	items, err := readItems(payload)
	if err != nil {
		return share{}, err
	}
	if len(items) < sharMinimumItems {
		return share{}, fmt.Errorf("shared folder has %d fields, expected at least %d", len(items), sharMinimumItems)
	}
	id := string(items[sharID])

	var keyHex string
	if len(items[sharKeyAES]) > 0 {
		// Usual case: a LastPass client already re-encrypted the sharing key with the vault key.
		keyHex, err = DecryptField(items[sharKeyAES], vaultKey)
	} else {
		keyHex, err = decryptSharingKeyRSA(items[sharKeyRSA], privateKey)
	}
	if err != nil {
		return share{}, fmt.Errorf("shared folder %s: %w", id, err)
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return share{}, fmt.Errorf("shared folder %s: %w", id, err)
	}
	name, err := DecryptField(items[sharName], key)
	if err != nil {
		return share{}, fmt.Errorf("shared folder %s: %w", id, err)
	}
	return share{id: id, name: name, key: key, readOnly: string(items[sharReadOnly]) == "1"}, nil
}

// decryptSharingKeyRSA handles a shared folder no LastPass client has opened
// yet: its sharing key is still encrypted with the account's public key.
func decryptSharingKeyRSA(encryptedHex []byte, privateKey *rsa.PrivateKey) (string, error) {
	if privateKey == nil {
		return "", errors.New("the account has no private key to open this shared folder: log in once with an official LastPass client")
	}
	encrypted, err := hex.DecodeString(string(encryptedHex))
	if err != nil {
		return "", err
	}
	// The official client uses RSA_PKCS1_OAEP_PADDING, which means SHA-1.
	keyHex, err := privateKey.Decrypt(rand.Reader, encrypted, &rsa.OAEPOptions{Hash: crypto.SHA1})
	if err != nil {
		return "", err
	}
	return string(keyHex), nil
}

// readItem reads one length-prefixed item (4-byte big endian size, then the
// payload) and returns it with the remaining data.
func readItem(data []byte) (item, rest []byte, err error) {
	if len(data) < 4 {
		return nil, nil, errors.New("vault is truncated")
	}
	size := binary.BigEndian.Uint32(data)
	data = data[4:]
	if uint64(size) > uint64(len(data)) {
		return nil, nil, errors.New("vault is truncated")
	}
	return data[:size], data[size:], nil
}

func readItems(data []byte) ([][]byte, error) {
	var items [][]byte
	for len(data) > 0 {
		item, rest, err := readItem(data)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
		data = rest
	}
	return items, nil
}
