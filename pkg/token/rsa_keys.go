package token

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"

	"github.com/eugenioenko/autentico/pkg/config"
)

var (
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
)

func init() {
	// Try to load from file,
	keyFile := config.Get().AuthJwkCertFile
	if _, err := os.Stat(keyFile); err == nil {
		pemBytes, err := os.ReadFile(keyFile)
		if err == nil {
			block, _ := pem.Decode(pemBytes)
			if block != nil && block.Type == "RSA PRIVATE KEY" {
				key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
				if err == nil {
					privateKey = key
					publicKey = &key.PublicKey
				}
			}
		}
	}
	// If not found, generate a new key pair
	if privateKey == nil {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err == nil {
			privateKey = key
			publicKey = &key.PublicKey
			pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
			os.WriteFile(keyFile, pemBytes, 0600)
		}
	}
}

func GetRSAPublicKey() *rsa.PublicKey {
	return publicKey
}

func GetRSAPublicKeyJWK(kid string) map[string]string {
	pub := GetRSAPublicKey()
	if pub == nil {
		return nil
	}
	return map[string]string{
		"kty": "RSA",
		"kid": kid,
		"use": "sig",
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(bigIntToBytes(pub.E)),
	}
}

func bigIntToBytes(e int) []byte {
	// Convert exponent to bytes
	b := make([]byte, 0)
	for e > 0 {
		b = append([]byte{byte(e & 0xff)}, b...)
		e >>= 8
	}
	return b
}
