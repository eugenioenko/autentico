package utils

import (
	"net/url"
	"strings"
)

// IsValidRedirectURI checks that the given URI is syntactically valid.
// HTTP(S) redirect URIs must include a host. Native-app redirect URIs may
// use a private-use scheme without a host, such as app.immich:///oauth-callback.
// Per-client redirect URI allowlist validation is handled separately at the client level.
func IsValidRedirectURI(uri string) bool {
	parsedURI, err := url.Parse(uri)
	if err != nil || parsedURI.Scheme == "" {
		return false
	}

	if parsedURI.Scheme == "http" || parsedURI.Scheme == "https" {
		return parsedURI.Host != ""
	}

	// Private-use/native-app schemes may use either an authority (myapp://callback)
	// or an absolute path without an authority (app.immich:///oauth-callback).
	return parsedURI.Host != "" || strings.HasPrefix(parsedURI.Path, "/")
}
