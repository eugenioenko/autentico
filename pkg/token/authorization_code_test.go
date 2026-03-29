package token

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// RFC 7636 §4.1: code_verifier = 43*128unreserved
// unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"

func TestValidateCodeVerifier_TooShort(t *testing.T) {
	err := validateCodeVerifier(strings.Repeat("a", 42))
	assert.Error(t, err, "RFC 7636 §4.1: verifier shorter than 43 chars must be rejected")
}

func TestValidateCodeVerifier_TooLong(t *testing.T) {
	err := validateCodeVerifier(strings.Repeat("a", 129))
	assert.Error(t, err, "RFC 7636 §4.1: verifier longer than 128 chars must be rejected")
}

func TestValidateCodeVerifier_MinLength(t *testing.T) {
	err := validateCodeVerifier(strings.Repeat("a", 43))
	assert.NoError(t, err, "43-char verifier must be accepted")
}

func TestValidateCodeVerifier_MaxLength(t *testing.T) {
	err := validateCodeVerifier(strings.Repeat("a", 128))
	assert.NoError(t, err, "128-char verifier must be accepted")
}

func TestValidateCodeVerifier_InvalidChars(t *testing.T) {
	// base64 standard chars (+, /) are NOT unreserved per RFC 3986
	verifier := strings.Repeat("a", 40) + "a+b"
	err := validateCodeVerifier(verifier)
	assert.Error(t, err, "RFC 7636 §4.1: '+' is not an unreserved char and must be rejected")

	verifier = strings.Repeat("a", 40) + "a/b"
	err = validateCodeVerifier(verifier)
	assert.Error(t, err, "RFC 7636 §4.1: '/' is not an unreserved char and must be rejected")

	verifier = strings.Repeat("a", 40) + "a b"
	err = validateCodeVerifier(verifier)
	assert.Error(t, err, "RFC 7636 §4.1: space is not an unreserved char and must be rejected")
}

func TestValidateCodeVerifier_AllUnreservedChars(t *testing.T) {
	// All unreserved chars from RFC 3986 §2.3: ALPHA / DIGIT / "-" / "." / "_" / "~"
	verifier := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	// pad to min length
	for len(verifier) < 43 {
		verifier += "a"
	}
	err := validateCodeVerifier(verifier)
	assert.NoError(t, err, "all unreserved chars must be accepted")
}
