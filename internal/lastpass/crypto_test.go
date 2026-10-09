package lastpass

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

var testKey = bytes.Repeat([]byte{0x2a}, keyLength)

// Reference values computed outside this code base, with Python's
// hashlib.pbkdf2_hmac: key = PBKDF2-SHA256(password, salt=username, 5000
// rounds), login hash = PBKDF2-SHA256(key, salt=password, 1 round).
func TestDeriveKeysKnownAnswer(t *testing.T) {
	const (
		wantKey  = "a63f69af0fce1cf95e5c8e9b45d9a5683fac6894b86b0acc890b108838debb62"
		wantHash = "f4b7593300ca55b5737fb749e926d85cddd0bb19c3008d3fc7ee4682914aa99d"
	)
	// LastPass salts with the lowercase username: the case must not matter.
	for _, username := range []string{"user@example.com", "User@Example.COM"} {
		hash, key, err := deriveKeys(username, "password", 5000)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(key) != wantKey || hash != wantHash {
			t.Errorf("deriveKeys(%q) = key %x, hash %s", username, key, hash)
		}
	}
}

func TestDeriveKeysRefusesTheLegacyScheme(t *testing.T) {
	if _, _, err := deriveKeys("user@example.com", "password", 1); err == nil {
		t.Error("a single iteration was accepted")
	}
}

// Reference ciphertext computed with `openssl enc -aes-256-cbc` for the key
// 0x2a x 32 and the IV 0x07 x 16, in each serialization LastPass uses.
func TestDecryptFieldKnownAnswer(t *testing.T) {
	const plaintext = "known answer"
	iv := bytes.Repeat([]byte{0x07}, aes.BlockSize)
	ciphertext, err := base64.StdEncoding.DecodeString("3x35RDkAy3JwNQIwP2SA8g==")
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"vault (raw)":    append(append([]byte("!"), iv...), ciphertext...),
		"write (base64)": []byte("!BwcHBwcHBwcHBwcHBwcHBw==|3x35RDkAy3JwNQIwP2SA8g=="),
	} {
		if decrypted, err := decryptField(data, testKey); err != nil || decrypted != plaintext {
			t.Errorf("%s: got %q, %v", name, decrypted, err)
		}
	}
}

func TestEncryptFieldRoundTrip(t *testing.T) {
	for _, plaintext := range []string{"a", "sixteen byte txt", "accents: éàü — and\nnewlines\n", strings.Repeat("long ", 500)} {
		encrypted, err := encryptField(plaintext, testKey)
		if err != nil {
			t.Fatal(err)
		}
		decrypted, err := decryptField([]byte(encrypted), testKey)
		if err != nil {
			t.Fatal(err)
		}
		if decrypted != plaintext {
			t.Errorf("round trip of %q gave %q", plaintext, decrypted)
		}
	}
}

func TestEmptyFieldStaysEmpty(t *testing.T) {
	encrypted, err := encryptField("", testKey)
	if err != nil || encrypted != "" {
		t.Errorf("encryptField(\"\") = %q, %v", encrypted, err)
	}
	decrypted, err := decryptField(nil, testKey)
	if err != nil || decrypted != "" {
		t.Errorf("decryptField(nil) = %q, %v", decrypted, err)
	}
}

// Entries nobody rewrote in years are still AES-ECB.
func TestDecryptFieldECB(t *testing.T) {
	const plaintext = "legacy value"
	block, err := aes.NewCipher(testKey)
	if err != nil {
		t.Fatal(err)
	}
	padded := pkcs7Pad([]byte(plaintext))
	ecb := make([]byte, len(padded))
	for i := 0; i < len(padded); i += aes.BlockSize {
		block.Encrypt(ecb[i:i+aes.BlockSize], padded[i:i+aes.BlockSize])
	}
	for name, data := range map[string][]byte{
		"raw":    ecb,
		"base64": []byte(base64.StdEncoding.EncodeToString(ecb)),
	} {
		if decrypted, err := decryptField(data, testKey); err != nil || decrypted != plaintext {
			t.Errorf("%s: got %q, %v", name, decrypted, err)
		}
	}
}

// The padding is the only integrity check of the format. With every padding
// byte verified, a wrong key passes it about once in 250 tries.
func TestDecryptFieldDetectsTheWrongKey(t *testing.T) {
	encrypted, err := encryptField("secret", testKey)
	if err != nil {
		t.Fatal(err)
	}
	const tries = 2000
	accepted := 0
	for i := range tries {
		wrongKey := bytes.Repeat([]byte{byte(i), byte(i >> 8), 0x55, 0xaa}, keyLength/4)
		if _, err := decryptField([]byte(encrypted), wrongKey); err == nil {
			accepted++
		}
	}
	if accepted > tries/50 {
		t.Errorf("%d wrong keys out of %d decrypted without error", accepted, tries)
	}
}
