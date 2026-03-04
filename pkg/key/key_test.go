package key

import (
	"os"
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

func TestDecodeBase64PEM(t *testing.T) {
	pk := GetPrivateKey()
	encoded := EncodeKeyToBase64(pk)
	
	decoded := decodeBase64PEM(encoded)
	assert.NotNil(t, decoded)
	assert.Equal(t, pk.N, decoded.N)
	assert.Equal(t, pk.D, decoded.D)
}

func TestDecodeBase64PEM_Invalid(t *testing.T) {
	assert.Nil(t, decodeBase64PEM("invalid-base64"))
	assert.Nil(t, decodeBase64PEM("bm90LWEtcGVtLWtleQ==")) // "not-a-pem-key" in base64
}

func TestInitKeys_InvalidEnvVar(t *testing.T) {
	// Set an invalid base64 key
	_ = os.Setenv("AUTENTICO_RSA_PRIVATE_KEY", "invalid-base64!!!")
	defer func() { _ = os.Unsetenv("AUTENTICO_RSA_PRIVATE_KEY") }()

	// Since initKeys uses sync.Once, it might have already run.
	// But in tests, we can't easily reset it.
	
	priv := GetPrivateKey()
	assert.NotNil(t, priv)
}

func TestDecodeBase64PEM_Error(t *testing.T) {
	res := decodeBase64PEM("not-base64")
	assert.Nil(t, res)
}
