package devicecode

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateDeviceCode(t *testing.T) {
	code, err := GenerateDeviceCode()
	require.NoError(t, err)
	// 20 bytes = 40 hex chars
	assert.Len(t, code, 40)

	// Ensure uniqueness
	code2, err := GenerateDeviceCode()
	require.NoError(t, err)
	assert.NotEqual(t, code, code2)
}

func TestGenerateUserCode(t *testing.T) {
	code, err := GenerateUserCode()
	require.NoError(t, err)
	assert.Len(t, code, 8)

	// All characters should be from the consonant alphabet
	for _, ch := range code {
		assert.Contains(t, userCodeAlphabet, string(ch))
	}
}

func TestGenerateUserCode_NoVowels(t *testing.T) {
	// Generate many codes and verify no vowels appear
	for range 100 {
		code, err := GenerateUserCode()
		require.NoError(t, err)
		for _, ch := range code {
			assert.NotContains(t, "AEIOU", string(ch))
		}
	}
}

func TestFormatUserCode(t *testing.T) {
	assert.Equal(t, "WDJB-MJHT", FormatUserCode("WDJBMJHT"))
	assert.Equal(t, "SHORT", FormatUserCode("SHORT"))
}

func TestNormalizeUserCode(t *testing.T) {
	assert.Equal(t, "WDJBMJHT", NormalizeUserCode("WDJB-MJHT"))
	assert.Equal(t, "WDJBMJHT", NormalizeUserCode("wdjb-mjht"))
	assert.Equal(t, "WDJBMJHT", NormalizeUserCode("wdjb mjht"))
	assert.Equal(t, "WDJBMJHT", NormalizeUserCode("  WDJB MJHT  "))
}
