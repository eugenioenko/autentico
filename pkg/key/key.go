package key

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"sync"

	"github.com/eugenioenko/autentico/pkg/config"
)

var (
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	once       sync.Once
)

func initKeys() {
	keyFile := config.Get().AuthPrivateKeyFile
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
	if privateKey == nil {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err == nil {
			privateKey = key
			publicKey = &key.PublicKey
			pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
			_ = os.WriteFile(keyFile, pemBytes, 0600)
		}
	}
}

func GetPrivateKey() *rsa.PrivateKey {
	once.Do(initKeys)
	return privateKey
}

func GetPublicKey() *rsa.PublicKey {
	once.Do(initKeys)
	return publicKey
}
