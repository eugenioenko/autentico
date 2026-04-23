package security

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Token validation and lifecycle tests.
//
// CVE-2020-14389 (Keycloak): token audience verification bypass
// CVE-2017-12160 (Keycloak): token usable after permission revocation
// CVE-2025-64521 (Authentik): deactivated service account still authenticates
// CVE-2021-32701 (Hydra): introspection cache ignores scope requirements

// CVE-2025-64521 (Authentik): deactivated user should not be able to use
// existing tokens — session must be invalidated.
func TestToken_DeactivatedUser_TokenRejected(t *testing.T) {
	ts := startTestServer(t)

	usr := createTestUser(t, "deact-user", "password123", "deact@test.com")
	tokens := obtainTokensViaROPC(t, ts, "test-client", "deact-user", "password123")

	// Verify token works
	status, _ := callUserinfo(t, ts, tokens.AccessToken)
	require.Equal(t, http.StatusOK, status)

	// Deactivate user
	err := user.DeactivateUser(usr.ID)
	require.NoError(t, err)

	// Token should now be rejected
	status, _ = callUserinfo(t, ts, tokens.AccessToken)
	assert.Equal(t, http.StatusUnauthorized, status,
		"deactivated user's access token should be rejected")
}

// CVE-2025-64521 (Authentik): deactivated user should not be able to
// obtain new tokens via ROPC.
func TestToken_DeactivatedUser_ROPCRejected(t *testing.T) {
	ts := startTestServer(t)

	usr := createTestUser(t, "deact-ropc", "password123", "deact-ropc@test.com")

	err := user.DeactivateUser(usr.ID)
	require.NoError(t, err)

	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", "test-client")
	form.Set("username", "deact-ropc")
	form.Set("password", "password123")

	resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.NotEqual(t, http.StatusOK, resp.StatusCode,
		"deactivated user should not get tokens via ROPC")
}

// CVE-2017-12160 (Keycloak): after token revocation via /revoke,
// the token must not be usable at /userinfo.
func TestToken_RevokedAccessToken_Rejected(t *testing.T) {
	ts := startTestServer(t)

	createTestUser(t, "revoke-user", "password123", "revoke@test.com")
	tokens := obtainTokensViaConfidentialROPC(t, ts, "revoke-user", "password123")

	// Verify works
	status, _ := callUserinfo(t, ts, tokens.AccessToken)
	require.Equal(t, http.StatusOK, status)

	// Revoke via /revoke endpoint
	form := url.Values{}
	form.Set("token", tokens.AccessToken)
	req, err := http.NewRequest("POST", ts.BaseURL+"/oauth2/revoke", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("sec-confidential", "sec-secret")

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode, "revocation should succeed")

	// Token must now be rejected
	status, _ = callUserinfo(t, ts, tokens.AccessToken)
	assert.Equal(t, http.StatusUnauthorized, status,
		"revoked access token should be rejected at /userinfo")
}

// CVE-2021-32701 (Hydra): introspection should respect token revocation.
func TestToken_RevokedToken_IntrospectionInactive(t *testing.T) {
	ts := startTestServer(t)

	createTestUser(t, "intro-user", "password123", "intro@test.com")
	tokens := obtainTokensViaConfidentialROPC(t, ts, "intro-user", "password123")

	// Revoke
	form := url.Values{}
	form.Set("token", tokens.AccessToken)
	req, err := http.NewRequest("POST", ts.BaseURL+"/oauth2/revoke", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("sec-confidential", "sec-secret")

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()

	// Introspect should return active=false
	form = url.Values{}
	form.Set("token", tokens.AccessToken)
	req, err = http.NewRequest("POST", ts.BaseURL+"/oauth2/introspect", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("sec-confidential", "sec-secret")

	resp, err = ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var result map[string]any
	err = json.Unmarshal(body, &result)
	require.NoError(t, err)

	assert.Equal(t, false, result["active"],
		"revoked token introspection should return active=false")
}

// Introspection of a completely fabricated token.
func TestToken_FabricatedToken_IntrospectionInactive(t *testing.T) {
	ts := startTestServer(t)

	form := url.Values{}
	form.Set("token", "totally-fabricated-token-12345")
	req, err := http.NewRequest("POST", ts.BaseURL+"/oauth2/introspect", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("sec-confidential", "sec-secret")

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var result map[string]any
	err = json.Unmarshal(body, &result)
	require.NoError(t, err)

	assert.Equal(t, false, result["active"],
		"fabricated token introspection should return active=false")
}
