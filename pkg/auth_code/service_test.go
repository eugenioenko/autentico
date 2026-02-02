package authcode

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateSecureCode(t *testing.T) {
	code, err := GenerateSecureCode()
	assert.NoError(t, err)
	assert.NotEmpty(t, code)
	assert.Len(t, code, 43) // Base64 URL encoding of 32 bytes
}

func TestGenerateSecureCode_Uniqueness(t *testing.T) {
	codes := make(map[string]bool)
	for i := 0; i < 100; i++ {
		code, err := GenerateSecureCode()
		assert.NoError(t, err)
		assert.False(t, codes[code], "Generated duplicate code")
		codes[code] = true
	}
}
