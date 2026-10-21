// Package totpsecret protects persisted authenticator seeds (RFC 6238 §5.1).
package totpsecret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
)

const EnvName = "AUTENTICO_TOTP_ENCRYPTION_KEY"
const Prefix = "totp:v1:"

// GenerateKey returns a random AES-256 key in canonical padded base64.
func GenerateKey() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

// ValidateKey never includes supplied key material in its errors.
func ValidateKey(encoded string) error {
	_, err := newAEAD(encoded)
	return err
}

func newAEAD(encoded string) (cipher.AEAD, error) {
	if encoded == "" {
		return nil, fmt.Errorf("%s is required; run 'autentico init' to add it to .env, or supply a persistent base64-encoded 32-byte key in the environment", EnvName)
	}
	key, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != encoded {
		return nil, fmt.Errorf("%s must be a base64-encoded 32-byte key", EnvName)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

// Seal uses a fresh nonce and binds ciphertext to its user and format version.
func Seal(key, userID, secret string) (string, error) {
	if secret == "" {
		return "", nil
	}
	aead, err := newAEAD(key)
	if err != nil {
		return "", err
	}
	// RFC 6238 §5.1: protect stored seeds; authenticating the owner also
	// prevents moving an encrypted enrollment to a different account.
	ciphertext := aead.Seal(nil, nil, []byte(secret), []byte(Prefix+userID))
	return Prefix + base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Open rejects plaintext, unsupported versions, tampering and wrong keys.
func Open(key, userID, stored string) (string, error) {
	if stored == "" {
		return "", nil
	}
	aead, err := newAEAD(key)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(stored, Prefix) {
		return "", fmt.Errorf("TOTP secret is not encrypted; run 'autentico migrate'")
	}
	data, err := base64.StdEncoding.Strict().DecodeString(strings.TrimPrefix(stored, Prefix))
	if err != nil || len(data) < aead.Overhead() {
		return "", fmt.Errorf("invalid encrypted TOTP secret")
	}
	plaintext, err := aead.Open(nil, nil, data, []byte(Prefix+userID))
	if err != nil {
		return "", fmt.Errorf("cannot decrypt TOTP secret: restore the original %s and verify database integrity", EnvName)
	}
	return string(plaintext), nil
}
