package lastpass

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"strings"
	"testing"
)

var testKey = bytes.Repeat([]byte{0x2a}, keyLength)

func TestEncryptFieldRoundTrip(t *testing.T) {
	for _, plaintext := range []string{"a", "sixteen byte txt", "accents: éàü — and\nnewlines\n", strings.Repeat("long ", 500)} {
		encrypted, err := EncryptField(plaintext, testKey)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(encrypted, "!") || !strings.Contains(encrypted, "|") {
			t.Errorf("unexpected serialization %q", encrypted)
		}
		decrypted, err := DecryptField([]byte(encrypted), testKey)
		if err != nil {
			t.Fatal(err)
		}
		if decrypted != plaintext {
			t.Errorf("round trip of %q gave %q", plaintext, decrypted)
		}
	}
}

func TestEmptyFieldStaysEmpty(t *testing.T) {
	encrypted, err := EncryptField("", testKey)
	if err != nil || encrypted != "" {
		t.Errorf("EncryptField(\"\") = %q, %v", encrypted, err)
	}
	decrypted, err := DecryptField(nil, testKey)
	if err != nil || decrypted != "" {
		t.Errorf("DecryptField(nil) = %q, %v", decrypted, err)
	}
}

// The vault can still hold fields in the serializations older clients wrote.
func TestDecryptFieldLegacySerializations(t *testing.T) {
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
	iv := bytes.Repeat([]byte{0x07}, aes.BlockSize)
	cbc := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(cbc, padded)

	for name, data := range map[string][]byte{
		"raw ECB":    ecb,
		"base64 ECB": []byte(base64.StdEncoding.EncodeToString(ecb)),
		"raw CBC":    append(append([]byte("!"), iv...), cbc...),
	} {
		decrypted, err := DecryptField(data, testKey)
		if err != nil || decrypted != plaintext {
			t.Errorf("%s: got %q, %v", name, decrypted, err)
		}
	}
}

func TestDecryptFieldRejectsTheWrongKey(t *testing.T) {
	encrypted, err := EncryptField("secret", testKey)
	if err != nil {
		t.Fatal(err)
	}
	wrongKey := bytes.Repeat([]byte{0x01}, keyLength)
	// A wrong key yields random padding: it is detected in all but a few cases
	// per thousand, never silently accepted as the right plaintext.
	if decrypted, err := DecryptField([]byte(encrypted), wrongKey); err == nil && decrypted == "secret" {
		t.Error("the wrong key decrypted the field")
	}
}

func TestDeriveKeysRefusesTheLegacyScheme(t *testing.T) {
	if _, _, err := DeriveKeys("user@example.com", "password", 1); err == nil {
		t.Error("a single iteration was accepted")
	}
}

// LastPass salts the vault key with the lowercase username.
func TestDeriveKeysIsCaseInsensitiveOnTheUsername(t *testing.T) {
	hashLower, keyLower, err := DeriveKeys("user@example.com", "password", 5000)
	if err != nil {
		t.Fatal(err)
	}
	hashUpper, keyUpper, err := DeriveKeys("User@Example.COM", "password", 5000)
	if err != nil {
		t.Fatal(err)
	}
	if hashLower != hashUpper || !bytes.Equal(keyLower, keyUpper) {
		t.Error("the username case changed the derived keys")
	}
	if len(keyLower) != keyLength || len(hashLower) != 2*keyLength {
		t.Errorf("unexpected key sizes: key %d bytes, hash %d characters", len(keyLower), len(hashLower))
	}
}
