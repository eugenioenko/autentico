package client

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRedirectWildcardIsOnePlainPathSegment(t *testing.T) {
	const pattern = "https://rp.example/test/*/callback"
	for _, tc := range []struct {
		name, candidate string
		valid           bool
	}{
		{"run ID", "https://rp.example/test/run-123_a.b~/callback", true},
		{"hidden name", "https://rp.example/test/.hidden/callback", true},
		{"conformance path", "https://rp.example/test/abc123/callback", true},
		{"nested path", "https://rp.example/test/a/plan/callback", false},
		{"traversal", "https://rp.example/test/a/../../other/callback", false},
		{"dot", "https://rp.example/test/./callback", false},
		{"dot dot", "https://rp.example/test/../callback", false},
		{"encoded dot", "https://rp.example/test/%2e/callback", false},
		{"encoded dot dot", "https://rp.example/test/%2E%2e/callback", false},
		{"double encoded traversal", "https://rp.example/test/%252e%252e/callback", false},
		{"encoded slash", "https://rp.example/test/a%2fb/callback", false},
		{"backslash", "https://rp.example/test/a\\b/callback", false},
		{"encoded backslash", "https://rp.example/test/a%5cb/callback", false},
		{"query injected before suffix", "https://rp.example/test/a?next=/callback", false},
		{"fragment injected before suffix", "https://rp.example/test/a#/callback", false},
		{"encoded query", "https://rp.example/test/a%3fnext%3d/callback", false},
		{"empty segment", "https://rp.example/test//callback", false},
		{"overlapping prefix suffix", "https://rp.example/test/callback", false},
		{"extra suffix", "https://rp.example/test/id/callback/extra", false},
		{"literal star", "https://rp.example/test/*/callback", false},
		{"other host", "https://evil.example/test/id/callback", false},
		{"other scheme", "http://rp.example/test/id/callback", false},
		{"other port", "https://rp.example:444/test/id/callback", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal([]string{pattern})
			require.NoError(t, err)
			registered := &Client{RedirectURIs: string(raw)}
			require.Equal(t, tc.valid, IsValidRedirectURI(registered, tc.candidate))
		})
	}
}

func TestRedirectWildcardPatternsAreValidatedAtRegistrationAndUse(t *testing.T) {
	for _, tc := range []struct {
		pattern, candidate string
		valid              bool
	}{
		{"https://rp.example/test/*/callback", "https://rp.example/test/id/callback", true},
		{"https://rp.example/*", "https://rp.example/identifier", true},
		{"https://rp.example/test/*/callback?fixed=1", "https://rp.example/test/id/callback?fixed=1", true},
		{"https://rp.example/test/pre*suf/callback", "https://rp.example/test/preIDsuf/callback", false},
		{"https://*.example/test/callback", "https://rp.example/test/callback", false},
		{"https://rp.example/callback?next=*", "https://rp.example/callback?next=evil", false},
		{"https://rp.example/test/id/callback#*", "https://rp.example/test/id/callback#evil", false},
		{"https://rp.example/test/*/*/callback", "https://rp.example/test/id/*/callback", false},
		{"https://rp.example/test/../*/callback", "https://rp.example/test/../id/callback", false},
		{"https://rp.example/test/%2e%2e/*/callback", "https://rp.example/test/%2e%2e/id/callback", false},
	} {
		t.Run(tc.pattern, func(t *testing.T) {
			raw, err := json.Marshal([]string{tc.pattern})
			require.NoError(t, err)
			// Direct construction models older rows that predate registration guards.
			require.Equal(t, tc.valid, IsValidRedirectURI(&Client{RedirectURIs: string(raw)}, tc.candidate))
			err = ValidateRedirectURIs([]string{tc.pattern})
			if tc.valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestRedirectWildcardKeepsFixedQueryAndExactRegistrations(t *testing.T) {
	patterns, err := json.Marshal([]string{"https://rp.example/test/*/callback?fixed=1", "https://rp.example/exact/%61?fixed=1"})
	require.NoError(t, err)
	registered := &Client{RedirectURIs: string(patterns)}
	require.True(t, IsValidRedirectURI(registered, "https://rp.example/test/id/callback?fixed=1"))
	require.False(t, IsValidRedirectURI(registered, "https://rp.example/test/id/callback?fixed=2"))
	require.False(t, IsValidRedirectURI(registered, "https://rp.example/test/id/callback?fixed=1&extra=2"))
	require.True(t, IsValidRedirectURI(registered, "https://rp.example/exact/%61?fixed=1"))
	require.False(t, IsValidRedirectURI(registered, "https://rp.example/exact/a?fixed=1"))
}

func TestRedirectWildcardPreservesConformanceAliasCallback(t *testing.T) {
	raw, err := json.Marshal([]string{"https://localhost.emobix.co.uk:8443/test/a/*/callback"})
	require.NoError(t, err)
	registered := &Client{RedirectURIs: string(raw)}
	require.True(t, IsValidRedirectURI(registered, "https://localhost.emobix.co.uk:8443/test/a/autentico/callback"))
	require.False(t, IsValidRedirectURI(registered, "https://localhost.emobix.co.uk:8443/test/a/alias/module/callback"))
	require.False(t, IsValidRedirectURI(registered, "https://localhost.emobix.co.uk:8443/test/a/../callback"))
}
