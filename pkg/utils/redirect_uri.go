package utils

import (
	"net/url"
)

// IsValidRedirectURI checks that the given URI is a syntactically valid URL
// with a scheme and host. Per-client redirect URI allowlist validation is
// handled separately at the client level.
func IsValidRedirectURI(uri string) bool {
	parsedURI, err := url.Parse(uri)
	if err != nil || parsedURI.Scheme == "" || parsedURI.Host == "" {
		return false
	}
	return true
}
