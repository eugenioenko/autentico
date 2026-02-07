package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateClientID(t *testing.T) {
	id, err := GenerateClientID()
	assert.NoError(t, err)
	assert.NotEmpty(t, id)
	// Base64 URL encoding of 16 bytes = 22 characters
	assert.Len(t, id, 22)
}

func TestGenerateClientID_Uniqueness(t *testing.T) {
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id, err := GenerateClientID()
		assert.NoError(t, err)
		assert.False(t, ids[id], "Generated duplicate client ID")
		ids[id] = true
	}
}

func TestGenerateClientSecret(t *testing.T) {
	secret, err := GenerateClientSecret()
	assert.NoError(t, err)
	assert.NotEmpty(t, secret)
	// Base64 URL encoding of 32 bytes = 43 characters
	assert.Len(t, secret, 43)
}

func TestGenerateClientSecret_Uniqueness(t *testing.T) {
	secrets := make(map[string]bool)
	for i := 0; i < 100; i++ {
		secret, err := GenerateClientSecret()
		assert.NoError(t, err)
		assert.False(t, secrets[secret], "Generated duplicate client secret")
		secrets[secret] = true
	}
}
