package key

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"log/slog"
	"sync"

	"github.com/eugenioenko/autentico/pkg/config"
)

var (
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	once       sync.Once
)

func initKeys() {
	b64 := config.GetBootstrap().PrivateKeyBase64
	if b64 != "" {
		if key := decodeBase64PEM(b64); key != nil {
			privateKey = key
			publicKey = &key.PublicKey
			return
		}
		slog.Warn("AUTENTICO_PRIVATE_KEY is set but could not be decoded — falling back to ephemeral key")
	}

	// No stable key configured: generate an ephemeral key and warn.
	slog.Warn("AUTENTICO_PRIVATE_KEY is not set. Using an ephemeral RSA key — all tokens will be invalidated on restart. Run 'autentico init' to generate a stable key.")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("key: failed to generate RSA key: " + err.Error())
	}
	privateKey = key
	publicKey = &key.PublicKey
}

// decodeBase64PEM decodes a base64-encoded PEM block into an RSA private key.
func decodeBase64PEM(b64 string) *rsa.PrivateKey {
	pemBytes, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil
	}
	return key
}

// EncodeKeyToBase64 encodes an RSA private key to a base64-encoded PEM string.
// Used by the init command when generating a new .env file.
func EncodeKeyToBase64(key *rsa.PrivateKey) string {
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	return base64.StdEncoding.EncodeToString(pemBytes)
}

func GetPrivateKey() *rsa.PrivateKey {
	once.Do(initKeys)
	return privateKey
}

func GetPublicKey() *rsa.PublicKey {
	once.Do(initKeys)
	return publicKey
}
