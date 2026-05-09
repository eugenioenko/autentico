package devicecode

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"strings"
)

// RFC 8628 §6.1: device_code must have at least 160 bits of entropy.
func GenerateDeviceCode() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// userCodeAlphabet uses consonants only to avoid generating recognizable words.
const userCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"

// GenerateUserCode generates an 8-character user code from the consonant alphabet.
// Displayed with a hyphen for readability (e.g., "WDJB-MJHT").
func GenerateUserCode() (string, error) {
	max := big.NewInt(int64(len(userCodeAlphabet)))
	var sb strings.Builder
	for i := 0; i < 8; i++ {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		sb.WriteByte(userCodeAlphabet[n.Int64()])
	}
	return sb.String(), nil
}

// FormatUserCode formats an 8-char code with a hyphen: "ABCDEFGH" -> "ABCD-EFGH"
func FormatUserCode(code string) string {
	if len(code) != 8 {
		return code
	}
	return code[:4] + "-" + code[4:]
}

// NormalizeUserCode strips hyphens/spaces and uppercases for comparison.
func NormalizeUserCode(input string) string {
	input = strings.ToUpper(input)
	input = strings.ReplaceAll(input, "-", "")
	input = strings.ReplaceAll(input, " ", "")
	return input
}
