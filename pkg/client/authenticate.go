package client

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// AuthenticateClient verifies the client credentials
// Returns the client if authentication succeeds, error otherwise
func AuthenticateClient(clientID, clientSecret string) (*Client, error) {
	client, err := ClientByClientID(clientID)
	if err != nil {
		return nil, fmt.Errorf("invalid client credentials")
	}

	if !client.IsActive {
		return nil, fmt.Errorf("client is inactive")
	}

	// Public clients don't require secret verification
	if client.ClientType == "public" {
		return client, nil
	}

	// Confidential clients must provide a valid secret
	if clientSecret == "" {
		return nil, fmt.Errorf("client secret required for confidential clients")
	}

	err = bcrypt.CompareHashAndPassword([]byte(client.ClientSecret), []byte(clientSecret))
	if err != nil {
		return nil, fmt.Errorf("invalid client credentials")
	}

	return client, nil
}

// ErrInvalidClientAuthenticationRequest distinguishes malformed authentication
// requests from credentials that fail authentication (RFC 6749 §5.2).
var ErrInvalidClientAuthenticationRequest = errors.New("invalid client authentication request")

// AuthenticateClientFromRequest accepts one credential mechanism, using body-only
// form credentials or exactly-once form-decoded OAuth Basic credentials. With no
// client credentials it leaves bearer authorization to the endpoint's policy.
func AuthenticateClientFromRequest(r *http.Request) (*Client, error) {
	// RFC 6749 §2.3.1 / §5.2: parse the body without accepting URI credentials,
	// duplicate credential parameters, or repeated Authorization headers.
	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("%w: malformed form body", ErrInvalidClientAuthenticationRequest)
	}
	query := r.URL.Query()
	for _, key := range []string{"client_id", "client_secret"} {
		for _, value := range query[key] {
			if value != "" {
				return nil, fmt.Errorf("%w: client credentials must be sent in the request body", ErrInvalidClientAuthenticationRequest)
			}
		}
		if len(r.PostForm[key]) > 1 {
			return nil, fmt.Errorf("%w: client credential parameters must not repeat", ErrInvalidClientAuthenticationRequest)
		}
	}
	if len(r.Header.Values("Authorization")) > 1 {
		return nil, fmt.Errorf("%w: use one authentication method", ErrInvalidClientAuthenticationRequest)
	}
	clientID, clientSecret := r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	authorization := strings.Fields(r.Header.Get("Authorization"))
	if len(authorization) > 0 && strings.EqualFold(authorization[0], "Basic") {
		// RFC 6749 §2.3.1: Base64 decoding alone does not reverse the required
		// form encoding. Decode once; malformed Basic never falls back.
		username, password, ok := r.BasicAuth()
		if !ok {
			return nil, fmt.Errorf("invalid Basic client credentials")
		}
		username, usernameErr := url.QueryUnescape(username)
		password, passwordErr := url.QueryUnescape(password)
		if usernameErr != nil || passwordErr != nil {
			return nil, fmt.Errorf("invalid Basic client credential encoding")
		}
		// RFC 6749 §2.3 / §5.2: a matching body client_id is identification;
		// a second secret or contradictory identity is not another fallback.
		if clientSecret != "" || (clientID != "" && clientID != username) {
			return nil, fmt.Errorf("%w: use one client credential set", ErrInvalidClientAuthenticationRequest)
		}
		return AuthenticateClient(username, password)
	}
	// RFC 6749 §5.2: bearer callers cannot also supply client credentials.
	if len(authorization) > 0 && (clientID != "" || clientSecret != "") {
		return nil, fmt.Errorf("%w: use one authentication method", ErrInvalidClientAuthenticationRequest)
	}
	if clientID == "" {
		if clientSecret != "" {
			return nil, fmt.Errorf("%w: client_id is required", ErrInvalidClientAuthenticationRequest)
		}
		return nil, nil
	}
	// RFC 6749 §2.3.1: confidential clients prove the secret; public clients
	// identify themselves without a shared password.
	return AuthenticateClient(clientID, clientSecret)
}

// IsValidRedirectURI checks if the given redirect URI is allowed for the client
func IsValidRedirectURI(client *Client, redirectURI string) bool {
	if client == nil {
		return true // Backward compatibility when no client is registered
	}

	allowedURIs := client.GetRedirectURIs()
	for _, uri := range allowedURIs {
		// RFC 9700 §2.1: compare exact registrations byte-for-byte. The explicit
		// conformance extension permits only one plain path segment.
		if strings.Contains(uri, "*") {
			if matchesRedirectWildcard(uri, redirectURI) {
				return true
			}
		} else if uri == redirectURI {
			return true
		}
	}
	return false
}

// IsGrantTypeAllowed checks if the given grant type is allowed for the client
func IsGrantTypeAllowed(client *Client, grantType string) bool {
	if client == nil {
		return true // Backward compatibility when no client is registered
	}

	allowedTypes := client.GetGrantTypes()
	for _, t := range allowedTypes {
		if t == grantType {
			return true
		}
	}
	return false
}

// FilterScopes returns the intersection of the requested scopes and the client's
// allowed scopes, preserving the original request order. If the client is nil or
// has no scopes configured, the requested scopes are returned unchanged.
func FilterScopes(c *Client, requested string) string {
	if c == nil || c.Scopes == "" {
		return requested
	}

	allowed := make(map[string]bool)
	for _, s := range strings.Fields(c.Scopes) {
		allowed[s] = true
	}

	var result []string
	for _, s := range strings.Fields(requested) {
		if allowed[s] {
			result = append(result, s)
		}
	}
	return strings.Join(result, " ")
}

// ValidateScopes returns true if every requested scope is within the client's
// allowed scopes. Returns true unconditionally when the client is nil, has no
// scopes configured, or the requested scope string is empty.
func ValidateScopes(c *Client, requested string) bool {
	if c == nil || c.Scopes == "" || requested == "" {
		return true
	}

	allowed := make(map[string]bool)
	for _, s := range strings.Fields(c.Scopes) {
		allowed[s] = true
	}

	for _, s := range strings.Fields(requested) {
		if !allowed[s] {
			return false
		}
	}
	return true
}

// IsResponseTypeAllowed checks if the given response type is allowed for the client
func IsResponseTypeAllowed(client *Client, responseType string) bool {
	if client == nil {
		return true // Backward compatibility when no client is registered
	}

	allowedTypes := client.GetResponseTypes()
	for _, t := range allowedTypes {
		if t == responseType {
			return true
		}
	}
	return false
}
