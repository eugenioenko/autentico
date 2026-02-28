package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsValidRedirectURI(t *testing.T) {
	tests := []struct {
		name     string
		uri      string
		expected bool
	}{
		{"Valid http URI", "http://localhost/callback", true},
		{"Valid https URI", "https://example.com/callback", true},
		{"Valid URI with port", "http://localhost:8080/callback", true},
		{"Empty URI", "", false},
		{"No scheme", "localhost/callback", false},
		{"No host", "http:///callback", false},
		{"Custom scheme", "myapp://callback", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidRedirectURI(tt.uri)
			assert.Equal(t, tt.expected, result)
		})
	}
}
