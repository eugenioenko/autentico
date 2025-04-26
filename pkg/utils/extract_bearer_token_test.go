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
