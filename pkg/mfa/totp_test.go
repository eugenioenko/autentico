package mfa

import (
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
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
