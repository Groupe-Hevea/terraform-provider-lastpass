package lastpass

import (
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
)

const (
	endpointLogin       = "/login.php"
	endpointVault       = "/getaccts.php"
	endpointShowWebsite = "/show_website.php"
	endpointLogout      = "/logout.php"
)

// defaultIterations is the first guess for the number of PBKDF2 rounds of the
// account. LastPass answers with the real value when the guess is wrong.
const defaultIterations = 100100

// ErrAccountNotFound is returned when an entry to update or delete does not exist.
var ErrAccountNotFound = errors.New("lastpass: entry not found")

// AuthenticationError is a login refused by LastPass.
type AuthenticationError struct {
	Cause   string
	Message string
}

func (e *AuthenticationError) Error() string {
	return fmt.Sprintf("lastpass: login refused (%s): %s", e.Cause, e.Message)
}

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
	c := &Client{http: &http.Client{Jar: jar}, baseURL: "https://lastpass.com"}
	for _, opt := range opts {
		opt(c)
	}

	iterations := defaultIterations
	for attempt := 0; ; attempt++ {
		loginHash, key, err := DeriveKeys(username, password, iterations)
		if err != nil {
			return nil, err
		}
		reply, err := c.post(ctx, endpointLogin, url.Values{
			"method":               {"cli"},
			"xml":                  {"2"},
			"username":             {strings.ToLower(username)},
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
			// A wrong guess of the iteration count is answered with the right one.
			if hint := attrs["iterations"]; hint != "" && attempt == 0 {
				if iterations, err = strconv.Atoi(hint); err != nil {
					return nil, fmt.Errorf("lastpass: unexpected iteration count %q", hint)
				}
				continue
			}
			return nil, &AuthenticationError{Cause: attrs["cause"], Message: attrs["message"]}
		}

		if c.token = attrs["token"]; c.token == "" {
			return nil, errors.New("lastpass: unexpected login reply: no session token")
		}
		c.key = key
		c.urlEncryption = attrs["url_encryption"] == "1"
		if c.privateKey, err = decryptPrivateKey(attrs["privatekeyenc"], key); err != nil {
			return nil, fmt.Errorf("lastpass: cannot decrypt the account private key: %w", err)
		}
		return c, nil
	}
}

// Logout ends the session.
func (c *Client) Logout(ctx context.Context) error {
	_, err := c.post(ctx, endpointLogout, url.Values{
		"method":     {"cli"},
		"noredirect": {"1"},
		"token":      {c.token},
	})
	return err
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+endpointVault+"?"+query.Encode(), nil)
	if err != nil {
		return nil, err
	}
	encoded, err := c.do(req)
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

// Add creates the entry and sets account.ID to the identifier LastPass
// assigned. vault must be a current snapshot: it provides the shared folders.
func (c *Client) Add(ctx context.Context, vault *Vault, account *Account) error {
	account.ID = "0"
	result, err := c.upsert(ctx, vault, account)
	if err != nil {
		return err
	}
	if result["msg"] != "accountadded" || result["aid"] == "" {
		return fmt.Errorf("lastpass: entry was not created (%s)", result["msg"])
	}
	account.ID = result["aid"]
	return nil
}

// Update overwrites the entry account.ID. An entry cannot change shared
// folder this way: account.Share must be the folder it already is in.
func (c *Client) Update(ctx context.Context, vault *Vault, account *Account) error {
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
func (c *Client) Delete(ctx context.Context, vault *Vault, account *Account) error {
	form := url.Values{
		"extjs":  {"1"},
		"delete": {"1"},
		"aid":    {account.ID},
		"token":  {c.token},
	}
	if _, err := c.addShare(form, vault, account); err != nil {
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

func (c *Client) upsert(ctx context.Context, vault *Vault, account *Account) (map[string]string, error) {
	if account.Name == "" {
		return nil, errors.New("lastpass: an entry needs a name")
	}
	form := url.Values{
		"extjs":     {"1"},
		"token":     {c.token},
		"method":    {"cli"},
		"pwprotect": {"off"},
		"aid":       {account.ID},
	}
	key, err := c.addShare(form, vault, account)
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
		encrypted, err := EncryptField(value, key)
		if err != nil {
			return nil, err
		}
		form.Set(param, encrypted)
	}
	// Like the official client: the URL is encrypted only when the account
	// has URL encryption enabled, and never for a secure note.
	if c.urlEncryption && account.URL != urlSecureNote {
		encrypted, err := EncryptField(account.URL, key)
		if err != nil {
			return nil, err
		}
		form.Set("url", encrypted)
	} else {
		form.Set("url", hex.EncodeToString([]byte(account.URL)))
	}
	return c.showWebsite(ctx, form)
}

// addShare resolves the shared folder of the entry, adds it to the request
// and returns the key that encrypts the entry.
func (c *Client) addShare(form url.Values, vault *Vault, account *Account) ([]byte, error) {
	if account.Share == "" {
		return c.key, nil
	}
	for _, s := range vault.shares {
		if s.name != account.Share {
			continue
		}
		if s.readOnly {
			return nil, fmt.Errorf("lastpass: shared folder %s is read-only for this account", s.name)
		}
		form.Set("sharedfolderid", s.id)
		return s.key, nil
	}
	return nil, fmt.Errorf("lastpass: shared folder %s not found: it does not exist or is not shared with this account", account.Share)
}

// showWebsite posts a write and returns the attributes of its <result>.
// LastPass answers a write on an unknown entry with an empty body.
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
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return c.do(req)
}

func (c *Client) do(req *http.Request) ([]byte, error) {
	res, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("lastpass: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("lastpass: %s %s: %s", req.Method, req.URL.Path, res.Status)
	}
	return io.ReadAll(res.Body)
}

// firstElement returns the name and attributes of the first XML element
// called one of names, wherever it sits in the document: LastPass wraps its
// answers differently from one endpoint and protocol version to the next.
func firstElement(document []byte, names ...string) (string, map[string]string, error) {
	decoder := xml.NewDecoder(strings.NewReader(string(document)))
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
