// Package lastpasstest provides an in-memory LastPass server for tests.
//
// It implements the endpoints the client uses with the wire formats of the
// real service, and with its own cryptography: it shares no code with the
// client, so that a mistake in one is not mirrored by the other.
package lastpasstest

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
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
	// iterations is far below a real account, to keep tests fast.
	iterations    = 5000
	sessionToken  = "test-session-token"
	sessionCookie = "PHPSESSID"
	urlSecureNote = "http://sn"
)

// Positions of the fields in an ACCT chunk, see account_parse in
// https://github.com/lastpass/lastpass-cli/blob/master/blob.c
const (
	posID              = 0
	posName            = 1
	posGroup           = 2
	posURL             = 3
	posNote            = 4
	posUsername        = 7
	posPassword        = 8
	posReprompt        = 9
	posLastTouch       = 12
	posLastModifiedGMT = 31
	fieldsPerAccount   = 40
)

// Failure is how the server mishandles a request, see Server.FailNext.
type Failure int

const (
	// Refuse answers an error without doing anything.
	Refuse Failure = iota
	// LoseReply does what is asked, then answers an error: for the client
	// the outcome is unknown.
	LoseReply
	// Ignore does nothing and answers an empty reply, the way LastPass
	// answers a write it does not act on.
	Ignore
)

// Server is a fake LastPass account.
type Server struct {
	*httptest.Server

	// URLEncryption is the feature flag sent at login.
	URLEncryption bool
	// LegacyPrivateKey serves the account private key in its original
	// hex serialization instead of the current one.
	LegacyPrivateKey bool
	// Truncated cuts the end marker off the vault, as an interrupted
	// download would.
	Truncated bool

	username  string
	password  string
	loginHash string
	key       []byte
	rsaKey    *rsa.PrivateKey

	mu        sync.Mutex
	accounts  []lastpass.Account
	corrupted map[string]bool
	shares    []*share
	nextID    int
	clock     int
	requests  []Request
	failures  map[string]Failure
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
	// unopened means no client ever re-encrypted the sharing key with the
	// vault key: it is only available encrypted with the account public key.
	unopened bool
}

// New starts a fake account; it is closed when the test ends.
func New(t testing.TB, username, password string) *Server {
	t.Helper()
	key, err := pbkdf2.Key(sha256.New, password, []byte(strings.ToLower(username)), iterations, 32)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := pbkdf2.Key(sha256.New, string(key), []byte(password), 1, 32)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		URLEncryption: true,
		username:      username,
		password:      password,
		loginHash:     hex.EncodeToString(hash),
		key:           key,
		rsaKey:        rsaKey,
		corrupted:     map[string]bool{},
		failures:      map[string]Failure{},
		nextID:        1000,
		clock:         1700000000,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login.php", s.handle(s.login))
	mux.HandleFunc("GET /getaccts.php", s.handle(s.authenticated(s.vault)))
	mux.HandleFunc("POST /show_website.php", s.handle(s.authenticated(s.showWebsite)))
	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

// AddShare creates a shared folder.
func (s *Server) AddShare(name string, readOnly bool) {
	s.addShare(&share{name: name, readOnly: readOnly})
}

// AddUnopenedShare creates a shared folder whose sharing key is only
// available encrypted with the account public key.
func (s *Server) AddUnopenedShare(name string) {
	s.addShare(&share{name: name, unopened: true})
}

func (s *Server) addShare(sh *share) {
	sh.key = random(32)
	s.mu.Lock()
	defer s.mu.Unlock()
	sh.id = strconv.Itoa(500 + len(s.shares))
	s.shares = append(s.shares, sh)
}

// Put stores an entry directly, as if another client had created it, and
// returns its ID.
func (s *Server) Put(account lastpass.Account) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.insert(account)
}

// Corrupt makes the entry undecryptable, as after a key mix-up.
func (s *Server) Corrupt(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.corrupted[id] = true
}

// FailNext makes the next request on path fail.
func (s *Server) FailNext(path string, failure Failure) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failures[path] = failure
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

// handle records the request and applies a pending failure. Handlers run
// with the lock held.
func (s *Server) handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		s.requests = append(s.requests, Request{Path: r.URL.Path, Form: r.Form})

		failure, failing := s.failures[r.URL.Path]
		delete(s.failures, r.URL.Path)
		switch {
		case failing && failure == Refuse:
			http.Error(w, "refused", http.StatusBadGateway)
		case failing && failure == LoseReply:
			next(httptest.NewRecorder(), r)
			http.Error(w, "reply lost", http.StatusBadGateway)
		case failing && failure == Ignore:
		default:
			next(w, r)
		}
	}
}

// authenticated requires the session cookie set at login, like the real
// service: the vault download carries no other credential.
func (s *Server) authenticated(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if cookie, err := r.Cookie(sessionCookie); err != nil || cookie.Value != sessionToken {
			http.Error(w, "not logged in", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	form := r.PostForm
	if form.Get("method") != "cli" || form.Get("xml") != "2" {
		http.Error(w, "unexpected client", http.StatusBadRequest)
		return
	}
	if form.Get("iterations") != strconv.Itoa(iterations) {
		fmt.Fprintf(w, `<response><error iterations="%d" /></response>`, iterations)
		return
	}
	if form.Get("username") != strings.ToLower(s.username) || form.Get("hash") != s.loginHash {
		fmt.Fprint(w, `<response><error message="Invalid Password!" cause="unknownpassword" /></response>`)
		return
	}
	flag := "0"
	if s.URLEncryption {
		flag = "1"
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: sessionToken, Path: "/"})
	fmt.Fprintf(w, `<response><ok uid="1" token="%s" privatekeyenc="%s" url_encryption="%s" /></response>`,
		sessionToken, s.encryptedPrivateKey(), flag)
}

func (s *Server) vault(w http.ResponseWriter, _ *http.Request) {
	var blob []byte
	for _, account := range s.accounts {
		if account.Share == "" {
			blob = append(blob, chunk("ACCT", s.encodeAccount(account, s.key))...)
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
	if !s.Truncated {
		blob = append(blob, chunk("ENDM", []byte("OK"))...)
	}
	fmt.Fprint(w, base64.StdEncoding.EncodeToString(blob))
}

func (s *Server) showWebsite(w http.ResponseWriter, r *http.Request) {
	form := r.PostForm
	if form.Get("token") != sessionToken {
		http.Error(w, "bad token", http.StatusForbidden)
		return
	}
	key, shareName := s.key, ""
	if id := form.Get("sharedfolderid"); id != "" {
		for _, sh := range s.shares {
			if sh.id == id {
				key, shareName = sh.key, sh.name
			}
		}
	}
	aid := form.Get("aid")

	// LastPass answers a write on an unknown entry with an empty body.
	if form.Get("delete") == "1" {
		index := s.find(aid, shareName)
		if index < 0 {
			return
		}
		s.accounts = append(s.accounts[:index], s.accounts[index+1:]...)
		fmt.Fprint(w, `<xmlresponse><result msg="accountdeleted" /></xmlresponse>`)
		return
	}

	account := lastpass.Account{
		Share:    shareName,
		Name:     decryptWire(form.Get("name"), key),
		Group:    decryptWire(form.Get("grouping"), key),
		Username: decryptWire(form.Get("username"), key),
		Password: decryptWire(form.Get("password"), key),
		Notes:    decryptWire(form.Get("extra"), key),
		Reprompt: form.Get("pwprotect") == "on",
	}
	if rawURL := form.Get("url"); strings.HasPrefix(rawURL, "!") {
		account.URL = decryptWire(rawURL, key)
	} else {
		account.URL = string(must(hex.DecodeString(rawURL)))
	}

	if aid == "0" {
		fmt.Fprintf(w, `<xmlresponse><result msg="accountadded" aid="%s" /></xmlresponse>`, s.insert(account))
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

// encodeAccount serializes an ACCT chunk. Like LastPass, it stores the URL of
// a secure note hex-encoded and the others according to the feature flag.
func (s *Server) encodeAccount(account lastpass.Account, key []byte) []byte {
	if s.corrupted[account.ID] {
		key = random(32)
	}
	reprompt := "0"
	if account.Reprompt {
		reprompt = "1"
	}
	fields := make([][]byte, fieldsPerAccount)
	fields[posID] = []byte(account.ID)
	fields[posName] = encryptBlob(account.Name, key)
	fields[posGroup] = encryptBlob(account.Group, key)
	fields[posNote] = encryptBlob(account.Notes, key)
	fields[posUsername] = encryptBlob(account.Username, key)
	fields[posPassword] = encryptBlob(account.Password, key)
	fields[posReprompt] = []byte(reprompt)
	fields[posLastTouch] = []byte(account.LastTouch)
	fields[posLastModifiedGMT] = []byte(account.LastModifiedGMT)
	if s.URLEncryption && account.URL != urlSecureNote {
		fields[posURL] = encryptBlob(account.URL, key)
	} else {
		fields[posURL] = []byte(hex.EncodeToString([]byte(account.URL)))
	}
	return items(fields...)
}

// encodeShare serializes a SHAR chunk: ID, sharing key encrypted with the
// account public key, name, read-only flag, an unused field, and the sharing
// key encrypted with the vault key once a client has opened the folder.
func (s *Server) encodeShare(sh *share) []byte {
	readOnly := "0"
	if sh.readOnly {
		readOnly = "1"
	}
	keyHex := hex.EncodeToString(sh.key)
	rsaEncrypted := must(rsa.EncryptOAEP(sha1.New(), rand.Reader, &s.rsaKey.PublicKey, []byte(keyHex), nil))
	var aesEncrypted []byte
	if !sh.unopened {
		aesEncrypted = encryptBlob(keyHex, s.key)
	}
	return items(
		[]byte(sh.id),
		[]byte(hex.EncodeToString(rsaEncrypted)),
		encryptBlob(sh.name, sh.key),
		[]byte(readOnly),
		nil,
		aesEncrypted,
	)
}

// encryptedPrivateKey is the account RSA key as login returns it: PKCS#8,
// hex-encoded, wrapped in markers and encrypted with the vault key.
func (s *Server) encryptedPrivateKey() string {
	der := must(x509.MarshalPKCS8PrivateKey(s.rsaKey))
	annotated := "LastPassPrivateKey<" + hex.EncodeToString(der) + ">LastPassPrivateKey"
	if s.LegacyPrivateKey {
		return hex.EncodeToString(encryptCBC(annotated, s.key, s.key[:aes.BlockSize]))
	}
	iv := random(aes.BlockSize)
	return "!" + base64.StdEncoding.EncodeToString(iv) + "|" + base64.StdEncoding.EncodeToString(encryptCBC(annotated, s.key, iv))
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

// encryptBlob encrypts a field as the vault holds it: "!", then the raw IV
// and ciphertext. An empty field stays empty.
func encryptBlob(plaintext string, key []byte) []byte {
	if plaintext == "" {
		return nil
	}
	iv := random(aes.BlockSize)
	return append(append([]byte("!"), iv...), encryptCBC(plaintext, key, iv)...)
}

// decryptWire decrypts a field as write requests carry it:
// "!<base64 iv>|<base64 ciphertext>".
func decryptWire(value string, key []byte) string {
	if value == "" {
		return ""
	}
	ivBase64, ciphertextBase64, found := strings.Cut(strings.TrimPrefix(value, "!"), "|")
	if !strings.HasPrefix(value, "!") || !found {
		panic("field is not in the write serialization: " + value)
	}
	iv := must(base64.StdEncoding.DecodeString(ivBase64))
	ciphertext := must(base64.StdEncoding.DecodeString(ciphertextBase64))
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(must(aes.NewCipher(key)), iv).CryptBlocks(plaintext, ciphertext)
	return string(plaintext[:len(plaintext)-int(plaintext[len(plaintext)-1])])
}

func encryptCBC(plaintext string, key, iv []byte) []byte {
	padding := aes.BlockSize - len(plaintext)%aes.BlockSize
	padded := append([]byte(plaintext), strings.Repeat(string(rune(padding)), padding)...)
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(must(aes.NewCipher(key)), iv).CryptBlocks(ciphertext, padded)
	return ciphertext
}

func random(size int) []byte {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func must[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}
