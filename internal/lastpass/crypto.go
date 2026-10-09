package lastpass

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const keyLength = 32

// deriveKeys returns the hash sent to LastPass to authenticate and the key
// that encrypts the vault. LastPass salts the key with the lowercase username.
func deriveKeys(username, password string, iterations int) (loginHash string, key []byte, err error) {
	if iterations < 2 {
		// A single iteration selects a legacy SHA-256 scheme that the official client refuses.
		return "", nil, fmt.Errorf("unsupported number of password iterations: %d", iterations)
	}
	key, err = pbkdf2.Key(sha256.New, password, []byte(strings.ToLower(username)), iterations, keyLength)
	if err != nil {
		return "", nil, err
	}
	hash, err := pbkdf2.Key(sha256.New, string(key), []byte(password), 1, keyLength)
	if err != nil {
		return "", nil, err
	}
	return hex.EncodeToString(hash), key, nil
}

// encryptField encrypts a field for a write request the way the official
// client does: AES-256-CBC, serialized as "!<base64 iv>|<base64 ciphertext>".
// An empty field stays empty.
func encryptField(plaintext string, key []byte) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	padded := pkcs7Pad([]byte(plaintext))
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)
	return "!" + base64.StdEncoding.EncodeToString(iv) + "|" + base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decryptField decrypts a field. The vault holds fields as "!" followed by
// the raw IV and ciphertext (AES-CBC); entries nobody rewrote in years can
// still be AES-ECB, and some values travel in the base64 forms.
func decryptField(data, key []byte) (string, error) {
	const ivBase64Len = 24 // base64 of a 16-byte IV

	size := len(data)
	switch {
	case size == 0:
		return "", nil

	case data[0] == '!' && size%aes.BlockSize == 1 && size > aes.BlockSize:
		return decryptCBC(data[1:1+aes.BlockSize], data[1+aes.BlockSize:], key)

	case data[0] == '!' && size > ivBase64Len+2 && data[ivBase64Len+1] == '|':
		iv, err := base64.StdEncoding.DecodeString(string(data[1 : ivBase64Len+1]))
		if err != nil {
			return "", err
		}
		ciphertext, err := base64.StdEncoding.DecodeString(string(data[ivBase64Len+2:]))
		if err != nil {
			return "", err
		}
		return decryptCBC(iv, ciphertext, key)

	case size%aes.BlockSize == 0:
		return decryptECB(data, key)

	default:
		ciphertext, err := base64.StdEncoding.DecodeString(string(data))
		if err != nil {
			return "", errors.New("field is not AES-256 encrypted")
		}
		return decryptECB(ciphertext, key)
	}
}

func decryptCBC(iv, ciphertext, key []byte) (string, error) {
	if len(iv) != aes.BlockSize || len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return "", errors.New("malformed AES-CBC field")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)
	return pkcs7Unpad(plaintext)
}

func decryptECB(ciphertext, key []byte) (string, error) {
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return "", errors.New("malformed AES-ECB field")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	plaintext := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i += aes.BlockSize {
		block.Decrypt(plaintext[i:i+aes.BlockSize], ciphertext[i:i+aes.BlockSize])
	}
	return pkcs7Unpad(plaintext)
}

func pkcs7Pad(data []byte) []byte {
	padding := aes.BlockSize - len(data)%aes.BlockSize
	return append(data, bytes.Repeat([]byte{byte(padding)}, padding)...)
}

// pkcs7Unpad removes the padding of a decrypted field. The padding is the
// only integrity check the format offers: a wrong key almost always breaks it.
func pkcs7Unpad(data []byte) (string, error) {
	padding := int(data[len(data)-1])
	if padding == 0 || padding > aes.BlockSize ||
		!bytes.Equal(data[len(data)-padding:], bytes.Repeat([]byte{byte(padding)}, padding)) {
		return "", errors.New("decryption failed: wrong key or corrupted field")
	}
	return string(data[:len(data)-padding]), nil
}

// decryptPrivateKey decrypts the account's RSA private key, which LastPass
// returns at login encrypted with the vault key. It is only needed for shared
// folders whose sharing key was never re-encrypted with the vault key. The
// result is nil when the account has no key pair yet.
func decryptPrivateKey(encrypted string, key []byte) (*rsa.PrivateKey, error) {
	var annotated string
	switch {
	case encrypted == "":
		return nil, nil
	case strings.HasPrefix(encrypted, "!"):
		// Current format: serialized like any other field.
		var err error
		if annotated, err = decryptField([]byte(encrypted), key); err != nil {
			return nil, err
		}
	default:
		// Original format: hex-encoded AES-CBC, with the start of the key as IV.
		ciphertext, err := hex.DecodeString(encrypted)
		if err != nil {
			return nil, err
		}
		if annotated, err = decryptCBC(key[:aes.BlockSize], ciphertext, key); err != nil {
			return nil, err
		}
	}
	keyHex := strings.TrimSuffix(strings.TrimPrefix(annotated, "LastPassPrivateKey<"), ">LastPassPrivateKey")
	der, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	privateKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("account private key is not an RSA key")
	}
	return privateKey, nil
}
