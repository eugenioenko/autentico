package mfa

import (
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTOTP(t *testing.T) {
	username := "testuser"
	issuer := "Autentico"

	secret, url, err := GenerateTotpSecret(username, issuer)
	assert.NoError(t, err)
	assert.NotEmpty(t, secret)
	assert.Contains(t, url, username)
	assert.Contains(t, url, issuer)

	// Validate with a real code
	code, err := totp.GenerateCode(secret, time.Now())
	assert.NoError(t, err)

	assert.True(t, ValidateTotpCode(secret, code))
	assert.False(t, ValidateTotpCode(secret, "000000"))
}

func TestValidateTotpCode_ValidCode(t *testing.T) {
	secret, _, err := GenerateTotpSecret("user1", "TestIssuer")
	require.NoError(t, err)

	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)

	assert.True(t, ValidateTotpCode(secret, code), "valid TOTP code should be accepted")
}

func TestValidateTotpCode_InvalidCode(t *testing.T) {
	secret, _, err := GenerateTotpSecret("user1", "TestIssuer")
	require.NoError(t, err)

	assert.False(t, ValidateTotpCode(secret, "999999"), "invalid TOTP code should be rejected")
	assert.False(t, ValidateTotpCode(secret, "123456"), "arbitrary 6-digit code should be rejected")
}

func TestValidateTotpCode_EmptyCode(t *testing.T) {
	secret, _, err := GenerateTotpSecret("user1", "TestIssuer")
	require.NoError(t, err)

	assert.False(t, ValidateTotpCode(secret, ""), "empty TOTP code should be rejected")
}

func TestValidateTotpCode_WrongLengthCode(t *testing.T) {
	secret, _, err := GenerateTotpSecret("user1", "TestIssuer")
	require.NoError(t, err)

	// Too short
	assert.False(t, ValidateTotpCode(secret, "123"), "3-digit code should be rejected")
	assert.False(t, ValidateTotpCode(secret, "12345"), "5-digit code should be rejected")

	// Too long
	assert.False(t, ValidateTotpCode(secret, "1234567"), "7-digit code should be rejected")
	assert.False(t, ValidateTotpCode(secret, "12345678"), "8-digit code should be rejected")

	// Single character
	assert.False(t, ValidateTotpCode(secret, "0"), "single-digit code should be rejected")
}

func TestValidateTotpCode_WrongSecret(t *testing.T) {
	secret1, _, err := GenerateTotpSecret("user1", "TestIssuer")
	require.NoError(t, err)

	secret2, _, err := GenerateTotpSecret("user2", "TestIssuer")
	require.NoError(t, err)

	// Generate a valid code for secret1
	code, err := totp.GenerateCode(secret1, time.Now())
	require.NoError(t, err)

	// Code from secret1 should not validate against secret2
	assert.True(t, ValidateTotpCode(secret1, code), "code should validate against its own secret")
	assert.False(t, ValidateTotpCode(secret2, code), "code from a different secret should be rejected")
}

func TestValidateTotpCode_NonNumericCode(t *testing.T) {
	secret, _, err := GenerateTotpSecret("user1", "TestIssuer")
	require.NoError(t, err)

	assert.False(t, ValidateTotpCode(secret, "abcdef"), "alphabetic code should be rejected")
	assert.False(t, ValidateTotpCode(secret, "12ab56"), "mixed alphanumeric code should be rejected")
	assert.False(t, ValidateTotpCode(secret, "      "), "whitespace code should be rejected")
}

func TestGenerateTotpSecret_ReturnsUniqueSecrets(t *testing.T) {
	secret1, url1, err := GenerateTotpSecret("user1", "TestIssuer")
	require.NoError(t, err)

	secret2, url2, err := GenerateTotpSecret("user2", "TestIssuer")
	require.NoError(t, err)

	assert.NotEqual(t, secret1, secret2, "different users should get different secrets")
	assert.NotEqual(t, url1, url2, "different users should get different OTP auth URLs")
}

func TestGenerateTotpSecret_URLContainsIssuerAndAccount(t *testing.T) {
	username := "alice@example.com"
	issuer := "MyAuthServer"

	secret, otpauthURL, err := GenerateTotpSecret(username, issuer)
	require.NoError(t, err)
	require.NotEmpty(t, secret)

	assert.Contains(t, otpauthURL, "otpauth://totp/")
	assert.Contains(t, otpauthURL, issuer)
	assert.Contains(t, otpauthURL, "secret="+secret)
}

func TestGenerateTotpSecret_GeneratedCodeValidates(t *testing.T) {
	// Full round-trip: generate secret, generate code from it, validate
	secret, _, err := GenerateTotpSecret("roundtrip-user", "Autentico")
	require.NoError(t, err)

	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	require.Len(t, code, 6, "generated code should be 6 digits")

	assert.True(t, ValidateTotpCode(secret, code), "freshly generated code should validate")
}

func TestValidateTotpCode_EmptySecret(t *testing.T) {
	// An empty secret should not validate any code
	assert.False(t, ValidateTotpCode("", "123456"), "empty secret should reject any code")
	assert.False(t, ValidateTotpCode("", ""), "empty secret and empty code should be rejected")
}
