package key

import (
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	testutils "github.com/eugenioenko/autentico/tests/utils"

	"github.com/stretchr/testify/assert"
)

func TestGetPrivateKey(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthPrivateKeyFile = "../../db/private_key.pem"
	})

	pk := GetPrivateKey()
	assert.NotNil(t, pk)
}

func TestGetPublicKey(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthPrivateKeyFile = "../../db/private_key.pem"
	})

	pub := GetPublicKey()
	assert.NotNil(t, pub)
}

func TestGetRSAPublicKeyJWK(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthPrivateKeyFile = "../../db/private_key.pem"
	})

	jwk := GetRSAPublicKeyJWK("test-kid")
	assert.NotNil(t, jwk)
	assert.Equal(t, "RSA", jwk["kty"])
	assert.Equal(t, "test-kid", jwk["kid"])
	assert.Equal(t, "sig", jwk["use"])
	assert.Equal(t, "RS256", jwk["alg"])
	assert.NotEmpty(t, jwk["n"])
	assert.NotEmpty(t, jwk["e"])
}

func TestBigIntToBytes(t *testing.T) {
	result := bigIntToBytes(65537)
	assert.NotEmpty(t, result)
	// 65537 = 0x010001
	assert.Equal(t, []byte{0x01, 0x00, 0x01}, result)
}

func TestBigIntToBytes_Zero(t *testing.T) {
	result := bigIntToBytes(0)
	assert.Empty(t, result)
}
