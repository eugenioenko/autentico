package utils

import (
	"net/url"
	"strings"
)

var allowedRedirectURIs = []string{
	"https://client.example.com/callback",
	"https://another-client.example.com/callback",
}

func IsValidRedirectURI(uri string) bool {
	parsedURI, err := url.Parse(uri)
	if err != nil || parsedURI.Scheme == "" || parsedURI.Host == "" {
		return false
	}

	for _, allowedURI := range allowedRedirectURIs {
		if strings.HasPrefix(uri, allowedURI) {
			return true
		}
	}

	return false
}
