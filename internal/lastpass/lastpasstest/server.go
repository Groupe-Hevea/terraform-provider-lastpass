// Package lastpasstest provides an in-memory LastPass server for tests. It
// implements the endpoints the client uses, with the real wire formats: the
// vault it serves is encrypted, and it decrypts what the client writes.
package lastpasstest

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/Groupe-Hevea/terraform-provider-lastpass/internal/lastpass"
)

const (
	token             = "test-session-token"
	fieldsPerAccount  = 40
	urlSecureNote     = "http://sn"
	initialTimestamp  = 1700000000
	sharingKeyLength  = 32
	firstAccountID    = 1000
	firstShareID      = 500
	posID             = 0
	posName           = 1
	posGroup          = 2
	posURL            = 3
	posNote           = 4
	posUsername       = 7
	posPassword       = 8
	posLastTouch      = 12
	posLastModifiedAt = 31
)

// Server is a fake LastPass account.
type Server struct {
	*httptest.Server

	// Iterations is the number of PBKDF2 rounds of the account.
	Iterations int
	// URLEncryption is the feature flag sent at login.
	URLEncryption bool

	username string
	password string

	mu            sync.Mutex
	key           []byte
	keyIterations int
	accounts      []lastpass.Account
	shares        []*share
	nextID        int
	clock         int
	requests      []Request
}

// Request is one call received by the server, with its decoded form.
type Request struct {
	Path string
	Form url.Values
}

type share struct {
	id       string
	name     string
	key      []byte
	readOnly bool
}

// New starts a fake account; it is closed when the test ends.
func New(t testing.TB, username, password string) *Server {
	t.Helper()
	s := &Server{
		Iterations:    5000, // far below a real account, to keep tests fast
		URLEncryption: true,
		username:      username,
		password:      password,
		nextID:        firstAccountID,
		clock:         initialTimestamp,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login.php", s.record(s.login))
	mux.HandleFunc("GET /getaccts.php", s.record(s.vault))
	mux.HandleFunc("POST /show_website.php", s.record(s.showWebsite))
	mux.HandleFunc("POST /logout.php", s.record(func(w http.ResponseWriter, r *http.Request) {}))
	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

// AddShare creates a shared folder.
func (s *Server) AddShare(name string, readOnly bool) {
	key := make([]byte, sharingKeyLength)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.shares = append(s.shares, &share{
		id:       strconv.Itoa(firstShareID + len(s.shares)),
		name:     name,
		key:      key,
		readOnly: readOnly,
	})
}

// Put stores an entry directly, as if another client had created it, and
// returns its ID.
func (s *Server) Put(account lastpass.Account) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.insert(account)
}

// Accounts returns the stored entries, in plaintext.
func (s *Server) Accounts() []lastpass.Account {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]lastpass.Account(nil), s.accounts...)
}

// Requests returns the calls received on path, oldest first.
func (s *Server) Requests(path string) []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	var matching []Request
	for _, r := range s.requests {
		if r.Path == path {
			matching = append(matching, r)
		}
	}
	return matching
}

func (s *Server) record(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		s.requests = append(s.requests, Request{Path: r.URL.Path, Form: r.Form})
		s.mu.Unlock()
		next(w, r)
	}
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if r.PostForm.Get("iterations") != strconv.Itoa(s.Iterations) {
		fmt.Fprintf(w, `<response><error iterations="%d" /></response>`, s.Iterations)
		return
	}
	expected, _, err := lastpass.DeriveKeys(s.username, s.password, s.Iterations)
	if err != nil {
		panic(err)
	}
	if r.PostForm.Get("username") != strings.ToLower(s.username) || r.PostForm.Get("hash") != expected {
		fmt.Fprint(w, `<response><error message="Invalid Password!" cause="unknownpassword" /></response>`)
		return
	}
	flag := "0"
	if s.URLEncryption {
		flag = "1"
	}
	fmt.Fprintf(w, `<response><ok uid="1" token="%s" privatekeyenc="" url_encryption="%s" /></response>`, token, flag)
}

func (s *Server) vault(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var blob []byte
	for _, account := range s.accounts {
		if account.Share == "" {
			blob = append(blob, chunk("ACCT", s.encodeAccount(account, s.userKey()))...)
		}
	}
	for _, sh := range s.shares {
		blob = append(blob, chunk("SHAR", s.encodeShare(sh))...)
		for _, account := range s.accounts {
			if account.Share == sh.name {
				blob = append(blob, chunk("ACCT", s.encodeAccount(account, sh.key))...)
			}
		}
	}
	blob = append(blob, chunk("ENDM", []byte("OK"))...)
	fmt.Fprint(w, base64.StdEncoding.EncodeToString(blob))
}

func (s *Server) showWebsite(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	form := r.PostForm
	if form.Get("token") != token {
		http.Error(w, "bad token", http.StatusForbidden)
		return
	}
	key, shareName := s.userKey(), ""
	if id := form.Get("sharedfolderid"); id != "" {
		for _, sh := range s.shares {
			if sh.id == id {
				key, shareName = sh.key, sh.name
			}
		}
	}
	aid := form.Get("aid")

	if form.Get("delete") == "1" {
		index := s.find(aid, shareName)
		if index < 0 {
			return // LastPass answers an empty body
		}
		s.accounts = append(s.accounts[:index], s.accounts[index+1:]...)
		fmt.Fprint(w, `<xmlresponse><result msg="accountdeleted" /></xmlresponse>`)
		return
	}

	account := lastpass.Account{
		Share:    shareName,
		Name:     decrypt(form.Get("name"), key),
		Group:    decrypt(form.Get("grouping"), key),
		Username: decrypt(form.Get("username"), key),
		Password: decrypt(form.Get("password"), key),
		Notes:    decrypt(form.Get("extra"), key),
	}
	if rawURL := form.Get("url"); strings.HasPrefix(rawURL, "!") {
		account.URL = decrypt(rawURL, key)
	} else {
		decoded, err := hex.DecodeString(rawURL)
		if err != nil {
			panic(err)
		}
		account.URL = string(decoded)
	}

	if aid == "0" {
		id := s.insert(account)
		fmt.Fprintf(w, `<xmlresponse><result msg="accountadded" aid="%s" /></xmlresponse>`, id)
		return
	}
	index := s.find(aid, shareName)
	if index < 0 {
		return
	}
	s.clock++
	account.ID = aid
	account.LastTouch = s.accounts[index].LastTouch
	account.LastModifiedGMT = strconv.Itoa(s.clock)
	s.accounts[index] = account
	fmt.Fprintf(w, `<xmlresponse><result msg="accountupdated" aid="%s" /></xmlresponse>`, aid)
}

func (s *Server) insert(account lastpass.Account) string {
	s.clock++
	account.ID = strconv.Itoa(s.nextID)
	account.LastTouch = strconv.Itoa(s.clock)
	account.LastModifiedGMT = strconv.Itoa(s.clock)
	s.nextID++
	s.accounts = append(s.accounts, account)
	return account.ID
}

func (s *Server) find(id, shareName string) int {
	for i, account := range s.accounts {
		if account.ID == id && account.Share == shareName {
			return i
		}
	}
	return -1
}

// userKey derives the vault key once per iteration count: key derivation is
// deliberately slow.
func (s *Server) userKey() []byte {
	if s.key == nil || s.keyIterations != s.Iterations {
		_, key, err := lastpass.DeriveKeys(s.username, s.password, s.Iterations)
		if err != nil {
			panic(err)
		}
		s.key, s.keyIterations = key, s.Iterations
	}
	return s.key
}

// encodeAccount serializes an ACCT chunk. Like LastPass, it stores the URL of
// a secure note hex-encoded and the others according to the feature flag.
func (s *Server) encodeAccount(account lastpass.Account, key []byte) []byte {
	fields := make([][]byte, fieldsPerAccount)
	fields[posID] = []byte(account.ID)
	fields[posName] = encrypt(account.Name, key)
	fields[posGroup] = encrypt(account.Group, key)
	fields[posNote] = encrypt(account.Notes, key)
	fields[posUsername] = encrypt(account.Username, key)
	fields[posPassword] = encrypt(account.Password, key)
	fields[posLastTouch] = []byte(account.LastTouch)
	fields[posLastModifiedAt] = []byte(account.LastModifiedGMT)
	if s.URLEncryption && account.URL != urlSecureNote {
		fields[posURL] = encrypt(account.URL, key)
	} else {
		fields[posURL] = []byte(hex.EncodeToString([]byte(account.URL)))
	}
	return items(fields...)
}

func (s *Server) encodeShare(sh *share) []byte {
	readOnly := "0"
	if sh.readOnly {
		readOnly = "1"
	}
	return items(
		[]byte(sh.id),
		nil, // sharing key encrypted with the account public key: left empty, the vault-key copy below is used
		encrypt(sh.name, sh.key),
		[]byte(readOnly),
		nil,
		encrypt(hex.EncodeToString(sh.key), s.userKey()),
	)
}

func chunk(id string, payload []byte) []byte {
	return append([]byte(id), items(payload)...)
}

func items(fields ...[]byte) []byte {
	var out []byte
	for _, field := range fields {
		out = binary.BigEndian.AppendUint32(out, uint32(len(field)))
		out = append(out, field...)
	}
	return out
}

func encrypt(plaintext string, key []byte) []byte {
	encrypted, err := lastpass.EncryptField(plaintext, key)
	if err != nil {
		panic(err)
	}
	return []byte(encrypted)
}

func decrypt(encrypted string, key []byte) string {
	plaintext, err := lastpass.DecryptField([]byte(encrypted), key)
	if err != nil {
		panic(err)
	}
	return plaintext
}
