package key

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetPrivateKey(t *testing.T) {
	pk := GetPrivateKey()
	assert.NotNil(t, pk)
}

func TestGetPublicKey(t *testing.T) {
	pub := GetPublicKey()
	assert.NotNil(t, pub)
}

func TestGetRSAPublicKeyJWK(t *testing.T) {
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

func TestEncodeKeyToBase64(t *testing.T) {
	pk := GetPrivateKey()
	encoded := EncodeKeyToBase64(pk)
	assert.NotEmpty(t, encoded)
}
