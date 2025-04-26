package utils

import (
	"autentico/pkg/config"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsValidRedirectURI(t *testing.T) {
	config.Values.AuthAllowedRedirectURIs = []string{"http://localhost/callback", "https://example.com/callback"}

	tests := []struct {
		name     string
		uri      string
		expected bool
	}{
		{"Valid URI", "http://localhost/callback", true},
		{"Invalid URI", "http://malicious.com/callback", false},
		{"Empty Allowed URIs", "http://anywhere.com/callback", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "Empty Allowed URIs" {
				config.Values.AuthAllowedRedirectURIs = []string{}
			}
			result := IsValidRedirectURI(tt.uri)
			assert.Equal(t, tt.expected, result)
		})
	}
}
