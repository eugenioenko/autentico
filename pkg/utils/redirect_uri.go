package utils

import (
	"autentico/pkg/config"
	"net/url"
	"strings"
)

func IsValidRedirectURI(uri string) bool {
	parsedURI, err := url.Parse(uri)
	if err != nil || parsedURI.Scheme == "" || parsedURI.Host == "" {
		return false
	}

	allowedRedirectURIs := config.Get().AuthAllowedRedirectURIs
	if len(allowedRedirectURIs) == 0 {
		// all redirect uris are allowed
		return true
	}

	for _, allowedURI := range allowedRedirectURIs {
		if strings.HasPrefix(uri, allowedURI) {
			return true
		}
	}

	return false
}
