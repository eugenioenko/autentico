package security

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Refresh token abuse tests.
//
// CVE-2026-1035 (Keycloak): refresh token reuse bypass (TOCTOU race)
// CVE-2022-3916 (Keycloak): offline session / refresh token reuse
// CVE-2020-15223 (Fosite): token revocation handler error leaks info
// CVE-2024-52287 (Authentik): scope escalation in device_code/client_credentials
// RFC 6749 §10.4: refresh token rotation — old token must be invalidated
// RFC 6749 §6: scope elevation via refresh must be rejected

// RFC 6749 §10.4: after rotation, old refresh token must be invalidated.
func TestRefreshToken_OldTokenInvalidatedAfterRotation(t *testing.T) {
	ts := startTestServer(t)

	createTestUser(t, "rot-user", "password123", "rot@test.com")
	tokens := obtainTokensViaROPC(t, ts, "test-client", "rot-user", "password123")

	// Rotate: use the refresh token
	newTokens := refreshTokens(t, ts, tokens.RefreshToken, "test-client")
	assert.NotEmpty(t, newTokens.RefreshToken)
	assert.NotEqual(t, tokens.RefreshToken, newTokens.RefreshToken,
		"new refresh token should differ from old one")

	// Old refresh token must now be rejected
	refreshTokensExpectError(t, ts, tokens.RefreshToken, "test-client", http.StatusBadRequest)
}

// RFC 6749 §10.4 + RFC 6819 §5.2.2.3: replaying a rotated-out refresh token
// should revoke the entire token family.
func TestRefreshToken_ReplayRevokesFamilyTokens(t *testing.T) {
	ts := startTestServer(t)

	createTestUser(t, "family-user", "password123", "family@test.com")
	tokens := obtainTokensViaROPC(t, ts, "test-client", "family-user", "password123")
	oldRefresh := tokens.RefreshToken

	// Rotate
	newTokens := refreshTokens(t, ts, oldRefresh, "test-client")

	// Replay old token — should trigger revocation cascade
	refreshTokensExpectError(t, ts, oldRefresh, "test-client", http.StatusBadRequest)

	// New refresh token should also be invalidated (family revocation)
	refreshTokensExpectError(t, ts, newTokens.RefreshToken, "test-client", http.StatusBadRequest)
}

// RFC 6749 §6: scope elevation via refresh must be rejected.
// Client cannot request broader scopes than the original grant.
func TestRefreshToken_ScopeElevationRejected(t *testing.T) {
	ts := startTestServer(t)

	createTestUser(t, "scope-user", "password123", "scope@test.com")

	// Obtain tokens with limited scope
	tokens := obtainTokensViaROPC(t, ts, "test-client", "scope-user", "password123")

	// Try to elevate scope on refresh
	_, status := refreshTokensWithScope(t, ts, tokens.RefreshToken, "test-client",
		"openid profile email offline_access admin", http.StatusBadRequest)
	assert.Equal(t, http.StatusBadRequest, status,
		"refresh with elevated scope must be rejected")
}

// Scope downscoping on refresh should succeed (RFC 6749 §6).
func TestRefreshToken_ScopeDownscopingAllowed(t *testing.T) {
	ts := startTestServer(t)

	createTestUser(t, "down-user", "password123", "down@test.com")
	tokens := obtainTokensViaROPC(t, ts, "test-client", "down-user", "password123")

	newTokens, status := refreshTokensWithScope(t, ts, tokens.RefreshToken, "test-client",
		"openid", http.StatusOK)
	assert.Equal(t, http.StatusOK, status)
	assert.NotEmpty(t, newTokens.AccessToken)
}

// Cross-client refresh must fail — refresh token bound to issuing client.
func TestRefreshToken_CrossClientRejected(t *testing.T) {
	ts := startTestServer(t)

	createTestUser(t, "xc-ref-user", "password123", "xc-ref@test.com")
	tokens := obtainTokensViaROPC(t, ts, "test-client", "xc-ref-user", "password123")

	// Try to use the refresh token with a different client
	refreshTokensExpectError(t, ts, tokens.RefreshToken, "other-client", http.StatusBadRequest)
}

// Completely fabricated refresh token must be rejected.
func TestRefreshToken_FabricatedToken(t *testing.T) {
	ts := startTestServer(t)

	refreshTokensExpectError(t, ts, "totally-fake-refresh-token", "test-client", http.StatusBadRequest)
}
