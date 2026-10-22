package client

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseMaxAgeCannotSilentlyDisableFreshness(t *testing.T) {
	for raw, want := range map[string]int64{"": -1, "0": 0, "60": 60, "9223372036854775807": math.MaxInt64} {
		actual, err := ParseMaxAge(raw)
		require.NoError(t, err)
		require.Equal(t, want, actual)
	}
	for _, raw := range []string{"-1", "+1", "1.5", " 1", "1 ", "9999999999999999999999"} {
		_, err := ParseMaxAge(raw)
		require.Error(t, err, raw)
	}
	require.Equal(t, "consent login", LoginPrompt("create consent"))
	require.Equal(t, "login consent", LoginPrompt("login create consent"))
}

func TestSilentPromptMustBeExclusive(t *testing.T) {
	for _, prompt := range []string{"", "none", "login consent", "create consent"} {
		if err := ValidatePrompt(prompt); err != nil {
			t.Fatalf("rejected %q: %v", prompt, err)
		}
	}
	for _, prompt := range []string{"none consent", "login none", "none none"} {
		if ValidatePrompt(prompt) == nil {
			t.Fatalf("accepted %q", prompt)
		}
	}
}
