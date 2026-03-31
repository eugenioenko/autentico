package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name       string
		authHeader string
		expected   string
	}{
		{"Valid Bearer Token", "Bearer abc123", "abc123"},
		{"Invalid Prefix", "Token abc123", ""},
		{"Empty Header", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := ExtractBearerToken(tt.authHeader)
			assert.Equal(t, tt.expected, token)
		})
	}
}

// RFC 6750 §2.1 / RFC 7235 §2.1: Bearer scheme name SHOULD be accepted case-insensitively.
func TestExtractBearerToken_CaseInsensitive(t *testing.T) {
	tests := []struct {
		name       string
		authHeader string
		wantToken  string
		wantEmpty  bool
	}{
		// Positive: all valid case variants must be accepted
		{"lowercase bearer", "bearer mytoken123", "mytoken123", false},
		{"uppercase BEARER", "BEARER mytoken123", "mytoken123", false},
		{"mixed case bEaReR", "bEaReR mytoken123", "mytoken123", false},
		{"canonical Bearer", "Bearer mytoken123", "mytoken123", false},
		// Negative: wrong scheme must still be rejected regardless of case
		{"basic scheme", "Basic dXNlcjpwYXNz", "", true},
		{"token scheme", "Token abc123", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractBearerToken(tt.authHeader)
			if tt.wantEmpty {
				assert.Empty(t, got, "non-Bearer scheme must be rejected")
			} else {
				assert.Equal(t, tt.wantToken, got)
			}
		})
	}
}
