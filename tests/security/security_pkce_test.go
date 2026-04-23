package security

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// PKCE downgrade and stripping tests.
//
// CVE-2024-23647 (Authentik): PKCE downgrade — removing code_challenge bypasses PKCE
// RFC 9700 §2.1.1: code_verifier must be required if code_challenge was sent
// RFC 7636 §4.6: wrong verifier must fail

// RFC 9700 §2.1.1: if code_challenge was sent at /authorize,
// code_verifier MUST be required at /token.
func TestPKCE_MissingVerifier(t *testing.T) {
	ts := startTestServer(t)
	redirectURI := "http://localhost:3000/callback"

	createTestUser(t, "pkce-user", "password123", "pkce@test.com")
	code := performAuthCodeFlow(t, ts, "test-client", redirectURI, "pkce-user", "password123", "s1")

	// Exchange without code_verifier — must fail
	exchangeCodeExpectError(t, ts, code, redirectURI, "test-client", "",
		http.StatusBadRequest, "invalid_grant")
}

// RFC 7636 §4.6: wrong code_verifier must fail.
func TestPKCE_WrongVerifier(t *testing.T) {
	ts := startTestServer(t)
	redirectURI := "http://localhost:3000/callback"

	createTestUser(t, "pkce-wrong", "password123", "pkce-wrong@test.com")
	code := performAuthCodeFlow(t, ts, "test-client", redirectURI, "pkce-wrong", "password123", "s1")

	// Exchange with incorrect verifier
	wrongVerifier := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	exchangeCodeExpectError(t, ts, code, redirectURI, "test-client", wrongVerifier,
		http.StatusBadRequest, "invalid_grant")
}

// PKCE verifier too short (must be 43-128 characters per RFC 7636 §4.1).
func TestPKCE_VerifierTooShort(t *testing.T) {
	ts := startTestServer(t)
	redirectURI := "http://localhost:3000/callback"

	createTestUser(t, "pkce-short", "password123", "pkce-short@test.com")
	code := performAuthCodeFlow(t, ts, "test-client", redirectURI, "pkce-short", "password123", "s1")

	shortVerifier := "tooshort"
	exchangeCodeExpectError(t, ts, code, redirectURI, "test-client", shortVerifier,
		http.StatusBadRequest, "invalid_grant")
}

// PKCE verifier with invalid characters.
func TestPKCE_VerifierInvalidChars(t *testing.T) {
	ts := startTestServer(t)
	redirectURI := "http://localhost:3000/callback"

	createTestUser(t, "pkce-chars", "password123", "pkce-chars@test.com")
	code := performAuthCodeFlow(t, ts, "test-client", redirectURI, "pkce-chars", "password123", "s1")

	// Contains spaces and special chars
	badVerifier := "this has spaces and !@#$% special chars padding"
	exchangeCodeExpectError(t, ts, code, redirectURI, "test-client", badVerifier,
		http.StatusBadRequest, "invalid_grant")
}

// RFC 9700 §2.1.1: plain method should be rejected; S256 is required.
func TestPKCE_PlainMethodRejected(t *testing.T) {
	ts := startTestServer(t)

	plainVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {"test-client"},
		"redirect_uri":          {"http://localhost:3000/callback"},
		"state":                 {"s1"},
		"code_challenge":        {plainVerifier},
		"code_challenge_method": {"plain"},
	}

	resp, err := ts.Client.Get(ts.BaseURL + "/oauth2/authorize?" + params.Encode())
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Server should reject plain method
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	loc := resp.Header.Get("Location")
	locURL, err := url.Parse(loc)
	require.NoError(t, err)
	assert.Contains(t, locURL.Query().Get("error"), "invalid_request",
		"plain code_challenge_method should be rejected")
}

// S256: verifier must hash to the challenge.
func TestPKCE_S256_CorrectVerifier(t *testing.T) {
	ts := startTestServer(t)
	redirectURI := "http://localhost:3000/callback"

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	createTestUser(t, "pkce-s256", "password123", "pkce-s256@test.com")
	code := performAuthCodeFlowWithPKCE(t, ts, "test-client", redirectURI,
		"pkce-s256", "password123", "s1", "openid", "", challenge, "S256")

	_ = exchangeCode(t, ts, code, redirectURI, "test-client", verifier)
}
