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
