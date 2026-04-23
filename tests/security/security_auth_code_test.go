package security

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Authorization code reuse and cross-client tests.
//
// CVE-2026-4282 (Keycloak): single-use code bypass / forged authorization codes
// RFC 6749 §4.1.2: code MUST be single-use; second use SHOULD revoke tokens
// RFC 6749 §10.5: code must be bound to client_id

// RFC 6749 §4.1.2: authorization code must be single-use.
// Second exchange must fail with invalid_grant.
func TestAuthCode_ReuseMustFail(t *testing.T) {
	ts := startTestServer(t)
	redirectURI := "http://localhost:3000/callback"

	createTestUser(t, "reuse-user", "password123", "reuse@test.com")
	code := performAuthCodeFlow(t, ts, "test-client", redirectURI, "reuse-user", "password123", "s1")

	// First exchange: should succeed
	_ = exchangeCode(t, ts, code, redirectURI, "test-client", testCodeVerifier)

	// Second exchange: must fail
	exchangeCodeExpectError(t, ts, code, redirectURI, "test-client", testCodeVerifier,
		http.StatusBadRequest, "invalid_grant")
}

// RFC 6749 §10.6: if a code is replayed after first use, tokens from the
// first exchange SHOULD be revoked (protective measure).
func TestAuthCode_ReplayRevokesTokens(t *testing.T) {
	ts := startTestServer(t)
	redirectURI := "http://localhost:3000/callback"

	createTestUser(t, "replay-user", "password123", "replay@test.com")
	code := performAuthCodeFlow(t, ts, "test-client", redirectURI, "replay-user", "password123", "s1")

	// First exchange
	tokens := exchangeCode(t, ts, code, redirectURI, "test-client", testCodeVerifier)

	// Second exchange (replay) — should fail
	exchangeCodeExpectError(t, ts, code, redirectURI, "test-client", testCodeVerifier,
		http.StatusBadRequest, "invalid_grant")

	// Access token from first exchange should now be revoked
	req, err := http.NewRequest("GET", ts.BaseURL+"/oauth2/userinfo", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"access token should be revoked after code replay")
}

// RFC 6749 §10.5: code must be bound to the client_id that requested it.
func TestAuthCode_CrossClientExchange(t *testing.T) {
	ts := startTestServer(t)
	redirectURI := "http://localhost:3000/callback"

	createTestUser(t, "xc-user", "password123", "xc@test.com")
	code := performAuthCodeFlow(t, ts, "test-client", redirectURI, "xc-user", "password123", "s1")

	// Try to exchange with a different client
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", "other-client")
	form.Set("code_verifier", testCodeVerifier)

	resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"exchanging code with wrong client_id must fail")

	body, _ := io.ReadAll(resp.Body)
	var errResp map[string]any
	_ = json.Unmarshal(body, &errResp)
	assert.Equal(t, "invalid_grant", errResp["error"])
}

// Redirect URI mismatch at exchange time.
func TestAuthCode_RedirectURIMismatch(t *testing.T) {
	ts := startTestServer(t)
	redirectURI := "http://localhost:3000/callback"

	createTestUser(t, "redir-user", "password123", "redir@test.com")
	code := performAuthCodeFlow(t, ts, "test-client", redirectURI, "redir-user", "password123", "s1")

	exchangeCodeExpectError(t, ts, code, "http://evil.com/callback", "test-client", testCodeVerifier,
		http.StatusBadRequest, "invalid_grant")
}

// Fabricated authorization code must be rejected.
func TestAuthCode_FabricatedCode(t *testing.T) {
	ts := startTestServer(t)

	exchangeCodeExpectError(t, ts, "totally-fake-code-12345", "http://localhost:3000/callback",
		"test-client", testCodeVerifier, http.StatusBadRequest, "invalid_grant")
}
