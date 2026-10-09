package lastpass

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	endpointIterations  = "/iterations.php"
	endpointLogin       = "/login.php"
	endpointVault       = "/getaccts.php"
	endpointShowWebsite = "/show_website.php"
)

// requestTimeout bounds every call. Writes run detached from the caller's
// cancellation (see the provider), so they need a limit of their own.
const requestTimeout = 2 * time.Minute

// LastPass throttles logins: a handful within a few seconds, which separate
// Terraform commands run in a row easily reach, are answered "429 Too Many
// Requests" for about a minute. A throttled request is retried after the
// delay LastPass asks for, or after throttleBackoff, 2x, 3x... otherwise.
const (
	throttleBackoff = 10 * time.Second
	throttleRetries = 4
)

// newAccountID is the ID a write request carries to create an entry.
const newAccountID = "0"

// ErrAccountNotFound is returned when LastPass answers a write with an empty
// reply, which is how it answers for an entry that does not exist. Nothing
// tells that case apart from another silent refusal: a caller that cares
// should check the vault.
var ErrAccountNotFound = errors.New("lastpass: entry not found")

// Client is an authenticated LastPass session.
type Client struct {
	http    *http.Client
	baseURL string

	token      string
	key        []byte
	privateKey *rsa.PrivateKey
	// urlEncryption tells whether LastPass expects entry URLs encrypted
	// (a per-account feature flag sent at login) rather than hex-encoded.
	urlEncryption bool
}

// Option customizes Login.
type Option func(*Client)

// WithBaseURL replaces https://lastpass.com, for tests.
func WithBaseURL(baseURL string) Option {
	return func(c *Client) { c.baseURL = baseURL }
}

// Login authenticates with a username and master password. Accounts that
// require a second factor are not supported.
func Login(ctx context.Context, username, password string, opts ...Option) (*Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	c := &Client{http: &http.Client{Jar: jar, Timeout: requestTimeout}, baseURL: "https://lastpass.com"}
	for _, opt := range opts {
		opt(c)
	}

	// Like the official client, ask for the number of PBKDF2 rounds of the
	// account first: guessing it would cost a refused login each time.
	email := strings.ToLower(username)
	reply, err := c.post(ctx, endpointIterations, url.Values{"email": {email}})
	if err != nil {
		return nil, err
	}
	iterations, err := strconv.Atoi(strings.TrimSpace(string(reply)))
	if err != nil {
		return nil, fmt.Errorf("lastpass: unexpected iteration count %q", reply)
	}
	loginHash, key, err := deriveKeys(username, password, iterations)
	if err != nil {
		return nil, fmt.Errorf("lastpass: %w", err)
	}
	reply, err = c.post(ctx, endpointLogin, url.Values{
		"method":               {"cli"},
		"xml":                  {"2"},
		"username":             {email},
		"hash":                 {loginHash},
		"iterations":           {strconv.Itoa(iterations)},
		"includeprivatekeyenc": {"1"},
	})
	if err != nil {
		return nil, err
	}
	element, attrs, err := firstElement(reply, "ok", "error")
	if err != nil {
		return nil, fmt.Errorf("lastpass: unexpected login reply: %w", err)
	}
	if element == "error" {
		return nil, fmt.Errorf("lastpass: login refused (%s): %s", attrs["cause"], attrs["message"])
	}
	if c.token = attrs["token"]; c.token == "" {
		return nil, errors.New("lastpass: unexpected login reply: no session token")
	}
	c.key = key
	c.urlEncryption = attrs["url_encryption"] == "1"
	// Like the official client, a private key that cannot be decrypted does
	// not prevent the login: only shared folders that need it are affected.
	c.privateKey, _ = decryptPrivateKey(attrs["privatekeyenc"], key)
	return c, nil
}

// Vault downloads and decrypts the whole vault. LastPass offers no way to
// fetch a single entry.
func (c *Client) Vault(ctx context.Context) (*Vault, error) {
	query := url.Values{
		"requestsrc": {"cli"},
		"mobile":     {"1"},
		"b64":        {"1"},
		"hasplugin":  {"1.3.3"},
	}
	encoded, err := c.do(ctx, func() (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+endpointVault+"?"+query.Encode(), nil)
	})
	if err != nil {
		return nil, err
	}
	blob, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		return nil, fmt.Errorf("lastpass: unexpected vault reply: %w", err)
	}
	vault, err := parseVault(blob, c.key, c.privateKey)
	if err != nil {
		return nil, fmt.Errorf("lastpass: %w", err)
	}
	return vault, nil
}

// Add creates the entry and returns the ID LastPass assigned; account.ID is
// ignored. vault must be a current snapshot: it provides the shared folders.
func (c *Client) Add(ctx context.Context, vault *Vault, account Account) (string, error) {
	account.ID = newAccountID
	result, err := c.upsert(ctx, vault, account)
	if err != nil {
		return "", err
	}
	if result["msg"] != "accountadded" || result["aid"] == "" {
		return "", fmt.Errorf("lastpass: entry was not created (%s)", result["msg"])
	}
	return result["aid"], nil
}

// Update overwrites the entry account.ID. An entry cannot change shared
// folder this way: account.Share must be the folder it already is in.
func (c *Client) Update(ctx context.Context, vault *Vault, account Account) error {
	result, err := c.upsert(ctx, vault, account)
	if err != nil {
		return err
	}
	if result["msg"] != "accountupdated" {
		return fmt.Errorf("lastpass: entry %s was not updated (%s)", account.ID, result["msg"])
	}
	return nil
}

// Delete removes the entry account.ID; only ID and Share are read.
func (c *Client) Delete(ctx context.Context, vault *Vault, account Account) error {
	form := url.Values{
		"extjs":  {"1"},
		"delete": {"1"},
		"aid":    {account.ID},
		"token":  {c.token},
	}
	if _, err := c.addShare(form, vault, account.Share); err != nil {
		return err
	}
	result, err := c.showWebsite(ctx, form)
	if err != nil {
		return err
	}
	if result["msg"] != "accountdeleted" {
		return fmt.Errorf("lastpass: entry %s was not deleted (%s)", account.ID, result["msg"])
	}
	return nil
}

func (c *Client) upsert(ctx context.Context, vault *Vault, account Account) (map[string]string, error) {
	if account.Name == "" {
		return nil, errors.New("lastpass: an entry needs a name")
	}
	reprompt := "off"
	if account.Reprompt {
		reprompt = "on"
	}
	form := url.Values{
		"extjs":     {"1"},
		"token":     {c.token},
		"method":    {"cli"},
		"pwprotect": {reprompt},
		"aid":       {account.ID},
	}
	key, err := c.addShare(form, vault, account.Share)
	if err != nil {
		return nil, err
	}
	for param, value := range map[string]string{
		"name":     account.Name,
		"grouping": account.Group,
		"username": account.Username,
		"password": account.Password,
		"extra":    account.Notes,
	} {
		encrypted, err := encryptField(value, key)
		if err != nil {
			return nil, fmt.Errorf("lastpass: %w", err)
		}
		form.Set(param, encrypted)
	}
	// Like the official client: the URL is encrypted only when the account
	// has URL encryption enabled, and never for a secure note.
	if c.urlEncryption && account.URL != urlSecureNote {
		encrypted, err := encryptField(account.URL, key)
		if err != nil {
			return nil, fmt.Errorf("lastpass: %w", err)
		}
		form.Set("url", encrypted)
	} else {
		form.Set("url", hex.EncodeToString([]byte(account.URL)))
	}
	return c.showWebsite(ctx, form)
}

// addShare resolves a shared folder by name, adds it to the request and
// returns the key that encrypts its entries. An empty name is the personal
// vault.
func (c *Client) addShare(form url.Values, vault *Vault, name string) ([]byte, error) {
	if name == "" {
		return c.key, nil
	}
	for _, s := range vault.shares {
		if s.name != name {
			continue
		}
		if s.readOnly {
			return nil, fmt.Errorf("lastpass: shared folder %s is read-only for this account", s.name)
		}
		form.Set("sharedfolderid", s.id)
		return s.key, nil
	}
	return nil, fmt.Errorf("lastpass: shared folder %s not found: it does not exist, is not shared with this account, or cannot be opened", name)
}

// showWebsite posts a write and returns the attributes of its <result>.
func (c *Client) showWebsite(ctx context.Context, form url.Values) (map[string]string, error) {
	reply, err := c.post(ctx, endpointShowWebsite, form)
	if err != nil {
		return nil, err
	}
	if len(reply) == 0 {
		return nil, ErrAccountNotFound
	}
	_, attrs, err := firstElement(reply, "result")
	if err != nil {
		return nil, fmt.Errorf("lastpass: unexpected reply to a write: %w", err)
	}
	return attrs, nil
}

func (c *Client) post(ctx context.Context, path string, form url.Values) ([]byte, error) {
	return c.do(ctx, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req, nil
	})
}

// do sends the request newRequest builds and returns the reply body. A
// throttled request was not processed: it is sent again, see throttleBackoff.
func (c *Client) do(ctx context.Context, newRequest func() (*http.Request, error)) ([]byte, error) {
	for attempt := 1; ; attempt++ {
		req, err := newRequest()
		if err != nil {
			return nil, err
		}
		res, err := c.http.Do(req)
		if err != nil {
			return nil, fmt.Errorf("lastpass: %w", err)
		}
		body, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("lastpass: %w", err)
		}
		switch {
		case res.StatusCode == http.StatusOK:
			return body, nil
		case res.StatusCode != http.StatusTooManyRequests || attempt > throttleRetries:
			return nil, fmt.Errorf("lastpass: %s %s: %s", req.Method, req.URL.Path, res.Status)
		}
		wait := time.Duration(attempt) * throttleBackoff
		if seconds, err := strconv.Atoi(res.Header.Get("Retry-After")); err == nil {
			wait = time.Duration(seconds) * time.Second
		}
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return nil, fmt.Errorf("lastpass: %s %s: throttled by LastPass: %w", req.Method, req.URL.Path, ctx.Err())
		}
	}
}

// firstElement returns the name and attributes of the first XML element
// called one of names, wherever it sits in the document: LastPass wraps its
// answers differently from one endpoint and protocol version to the next.
func firstElement(document []byte, names ...string) (string, map[string]string, error) {
	decoder := xml.NewDecoder(bytes.NewReader(document))
	for {
		token, err := decoder.Token()
		if err != nil {
			return "", nil, fmt.Errorf("no <%s> element: %w", strings.Join(names, "> or <"), err)
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		for _, name := range names {
			if start.Name.Local == name {
				attrs := make(map[string]string, len(start.Attr))
				for _, attr := range start.Attr {
					attrs[attr.Name.Local] = attr.Value
				}
				return name, attrs, nil
			}
		}
	}
}
