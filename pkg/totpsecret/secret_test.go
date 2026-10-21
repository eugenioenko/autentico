package totpsecret

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncryptionRoundTripAndOwnerBinding(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)
	require.NoError(t, ValidateKey(key))
	first, err := Seal(key, "alice", "JBSWY3DPEHPK3PXP")
	require.NoError(t, err)
	second, err := Seal(key, "alice", "JBSWY3DPEHPK3PXP")
	require.NoError(t, err)
	require.NotEqual(t, first, second, "encryption must use fresh random nonces")
	require.NotContains(t, first, "JBSWY3DPEHPK3PXP")
	plain, err := Open(key, "alice", first)
	require.NoError(t, err)
	require.Equal(t, "JBSWY3DPEHPK3PXP", plain)
	_, err = Open(key, "bob", first)
	require.Error(t, err, "ciphertext cannot be copied between accounts")
	other, err := GenerateKey()
	require.NoError(t, err)
	_, err = Open(other, "alice", first)
	require.ErrorContains(t, err, "restore the original "+EnvName)
	data, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(first, Prefix))
	require.NoError(t, err)
	data[len(data)-1] ^= 1
	_, err = Open(key, "alice", Prefix+base64.StdEncoding.EncodeToString(data))
	require.Error(t, err)
}

func TestRejectInvalidKeysAndStoredFormats(t *testing.T) {
	for _, key := range []string{"", "invalid-secret", base64.StdEncoding.EncodeToString(make([]byte, 16)), base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n"} {
		require.ErrorContains(t, ValidateKey(key), EnvName)
		_, err := Seal(key, "alice", "seed")
		require.Error(t, err)
		require.NotContains(t, err.Error(), "invalid-secret")
	}
	key, err := GenerateKey()
	require.NoError(t, err)
	for _, stored := range []string{"plaintext", "totp:v2:AAAA", Prefix, Prefix + "!", Prefix + "AAAA"} {
		_, err := Open(key, "alice", stored)
		require.Error(t, err, stored)
	}
	empty, err := Open("", "alice", "")
	require.NoError(t, err)
	require.Empty(t, empty)
}
