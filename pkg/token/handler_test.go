package token

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/user"
	testutils "github.com/eugenioenko/autentico/tests/utils"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// insertROPCTestClient seeds a public OAuth2 client that allows password and refresh_token grants.
func insertROPCTestClient(t *testing.T) {
	t.Helper()
	_, err := db.GetDB().Exec(`
		INSERT INTO clients (id, client_id, client_name, client_type, redirect_uris, grant_types, is_active)
		VALUES ('ropc-test-id', 'ropc-test-client', 'ROPC Test Client', 'public', '[]', '["password","refresh_token"]', TRUE)
	`)
	if err != nil {
		t.Fatalf("failed to insert ROPC test client: %v", err)
	}
}

func TestHandleToken(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AuthRefreshTokenCookieOnly = false
	})

	// Create a test user and a registered client
	_, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)
	insertROPCTestClient(t)

	// Perform token request
	form := url.Values{}
	form.Add("grant_type", "password")
	form.Add("client_id", "ropc-test-client")
	form.Add("username", "testuser")
	form.Add("password", "password123")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleToken(rr, req)

	// Verify the response
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "access_token")
	assert.Contains(t, rr.Body.String(), "refresh_token")
}

func TestHandleToken_NonPostMethod(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/token", nil)
	rr := httptest.NewRecorder()

	HandleToken(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Only POST method is allowed")
}

func TestHandleToken_InvalidGrantType(t *testing.T) {
	testutils.WithTestDB(t)

	form := url.Values{}
	form.Add("grant_type", "invalid")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleToken(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_request")
}

func TestHandleToken_MissingGrantType(t *testing.T) {
	testutils.WithTestDB(t)

	form := url.Values{}

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleToken(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_request")
}

func TestHandleToken_PasswordGrant_InvalidCredentials(t *testing.T) {
	testutils.WithTestDB(t)

	_, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)
	insertROPCTestClient(t)

	form := url.Values{}
	form.Add("grant_type", "password")
	form.Add("client_id", "ropc-test-client")
	form.Add("username", "testuser")
	form.Add("password", "wrongpassword")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleToken(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_grant")
}

func TestHandleToken_PasswordGrant_MissingUsername(t *testing.T) {
	testutils.WithTestDB(t)

	form := url.Values{}
	form.Add("grant_type", "password")
	form.Add("password", "password123")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleToken(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_request")
}

func TestHandleToken_AuthorizationCodeGrant(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AuthRefreshTokenCookieOnly = false
	})

	usr, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	// Create an auth code
	code := authcode.AuthCode{
		Code:        "test-auth-code",
		UserID:      usr.ID,
		ClientID:    "",
		RedirectURI: "http://localhost/callback",
		Scope:       "read write",
		ExpiresAt:   time.Now().Add(10 * time.Minute),
		Used:        false,
	}
	err = authcode.CreateAuthCode(code)
	assert.NoError(t, err)

	form := url.Values{}
	form.Add("grant_type", "authorization_code")
	form.Add("code", "test-auth-code")
	form.Add("redirect_uri", "http://localhost/callback")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleToken(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "access_token")
}

func TestHandleToken_AuthorizationCodeGrant_MissingCode(t *testing.T) {
	testutils.WithTestDB(t)

	form := url.Values{}
	form.Add("grant_type", "authorization_code")
	form.Add("redirect_uri", "http://localhost/callback")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleToken(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_request")
}

func TestHandleToken_AuthorizationCodeGrant_InvalidCode(t *testing.T) {
	testutils.WithTestDB(t)

	form := url.Values{}
	form.Add("grant_type", "authorization_code")
	form.Add("code", "nonexistent-code")
	form.Add("redirect_uri", "http://localhost/callback")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleToken(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_grant")
}

func TestHandleToken_AuthorizationCodeGrant_UsedCode(t *testing.T) {
	testutils.WithTestDB(t)

	usr, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	code := authcode.AuthCode{
		Code:        "used-code",
		UserID:      usr.ID,
		RedirectURI: "http://localhost/callback",
		Scope:       "read write",
		ExpiresAt:   time.Now().Add(10 * time.Minute),
		Used:        false,
	}
	err = authcode.CreateAuthCode(code)
	assert.NoError(t, err)

	// Mark as used
	err = authcode.MarkAuthCodeAsUsed("used-code")
	assert.NoError(t, err)

	form := url.Values{}
	form.Add("grant_type", "authorization_code")
	form.Add("code", "used-code")
	form.Add("redirect_uri", "http://localhost/callback")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleToken(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_grant")
}

// RFC 6749 §4.1.2: when a used auth code is presented again, previously issued tokens must be revoked
func TestHandleToken_AuthorizationCodeReuse_RevokesIssuedTokens(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "code-client", []string{"http://localhost/callback"})

	usr, err := user.CreateUser("reuse-user", "password123", "reuse@example.com")
	assert.NoError(t, err)

	// Seed a previously issued token as if it came from an authorization_code exchange
	_, err = db.GetDB().Exec(`
		INSERT INTO tokens (id, user_id, access_token, refresh_token, access_token_type,
			refresh_token_expires_at, access_token_expires_at, issued_at, scope, grant_type)
		VALUES ('tok-reuse-1', ?, 'reuse-access-token', 'reuse-refresh-token', 'Bearer',
			datetime('now', '+30 days'), datetime('now', '+15 minutes'), datetime('now'), 'openid', 'authorization_code')
	`, usr.ID)
	assert.NoError(t, err)

	// Present a reused (already-used) auth code
	code := authcode.AuthCode{
		Code:        "reuse-code",
		UserID:      usr.ID,
		ClientID:    "code-client",
		RedirectURI: "http://localhost/callback",
		Scope:       "openid",
		ExpiresAt:   time.Now().Add(10 * time.Minute),
	}
	assert.NoError(t, authcode.CreateAuthCode(code))
	assert.NoError(t, authcode.MarkAuthCodeAsUsed("reuse-code"))

	form := url.Values{}
	form.Add("grant_type", "authorization_code")
	form.Add("code", "reuse-code")
	form.Add("redirect_uri", "http://localhost/callback")
	form.Add("client_id", "code-client")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleToken(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_grant")

	// Previously issued token must now be revoked
	var revokedAt *string
	err = db.GetDB().QueryRow(`SELECT revoked_at FROM tokens WHERE id = 'tok-reuse-1'`).Scan(&revokedAt)
	assert.NoError(t, err)
	assert.NotNil(t, revokedAt, "token issued for this user must be revoked on code reuse")
}

func TestHandleToken_AuthorizationCodeGrant_ExpiredCode(t *testing.T) {
	testutils.WithTestDB(t)

	usr, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	code := authcode.AuthCode{
		Code:        "expired-code",
		UserID:      usr.ID,
		RedirectURI: "http://localhost/callback",
		Scope:       "read write",
		ExpiresAt:   time.Now().Add(-10 * time.Minute), // expired
		Used:        false,
	}
	err = authcode.CreateAuthCode(code)
	assert.NoError(t, err)

	form := url.Values{}
	form.Add("grant_type", "authorization_code")
	form.Add("code", "expired-code")
	form.Add("redirect_uri", "http://localhost/callback")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleToken(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_grant")
}

func TestHandleToken_AuthorizationCodeGrant_RedirectMismatch(t *testing.T) {
	testutils.WithTestDB(t)

	usr, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	code := authcode.AuthCode{
		Code:        "redirect-mismatch-code",
		UserID:      usr.ID,
		RedirectURI: "http://localhost/callback",
		Scope:       "read write",
		ExpiresAt:   time.Now().Add(10 * time.Minute),
		Used:        false,
	}
	err = authcode.CreateAuthCode(code)
	assert.NoError(t, err)

	form := url.Values{}
	form.Add("grant_type", "authorization_code")
	form.Add("code", "redirect-mismatch-code")
	form.Add("redirect_uri", "http://different-host/callback")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleToken(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_grant")
}

func TestHandleToken_AuthorizationCodeGrant_ClientIDMismatch(t *testing.T) {
	testutils.WithTestDB(t)

	usr, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	// Register the client being sent in the request so auth passes before the mismatch check
	_, err = db.GetDB().Exec(`
		INSERT INTO clients (id, client_id, client_name, client_type, redirect_uris, grant_types, is_active)
		VALUES ('diff-client-id', 'different-client', 'Different Client', 'public', '["http://localhost/callback"]', '["authorization_code"]', TRUE)
	`)
	assert.NoError(t, err)

	code := authcode.AuthCode{
		Code:        "client-mismatch-code",
		UserID:      usr.ID,
		ClientID:    "original-client",
		RedirectURI: "http://localhost/callback",
		Scope:       "read write",
		ExpiresAt:   time.Now().Add(10 * time.Minute),
		Used:        false,
	}
	err = authcode.CreateAuthCode(code)
	assert.NoError(t, err)

	form := url.Values{}
	form.Add("grant_type", "authorization_code")
	form.Add("code", "client-mismatch-code")
	form.Add("redirect_uri", "http://localhost/callback")
	form.Add("client_id", "different-client")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleToken(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Client ID mismatch")
}

func TestHandleToken_RefreshTokenGrant(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AuthRefreshTokenCookieOnly = false
	})

	// Create user and get tokens via password grant
	_, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)
	insertROPCTestClient(t)

	form := url.Values{}
	form.Add("grant_type", "password")
	form.Add("client_id", "ropc-test-client")
	form.Add("username", "testuser")
	form.Add("password", "password123")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleToken(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	var tokenResp TokenResponse
	err = json.Unmarshal(rr.Body.Bytes(), &tokenResp)
	assert.NoError(t, err)

	// Now use refresh token to get new tokens
	form2 := url.Values{}
	form2.Add("grant_type", "refresh_token")
	form2.Add("refresh_token", tokenResp.RefreshToken)

	req2 := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr2 := httptest.NewRecorder()

	HandleToken(rr2, req2)

	assert.Equal(t, http.StatusOK, rr2.Code)
	assert.Contains(t, rr2.Body.String(), "access_token")
}

// TestHandleToken_RefreshTokenGrant_ScopeInResponse verifies that the refresh_token
// grant includes the scope in the token response per RFC 6749 §5.1.
func TestHandleToken_RefreshTokenGrant_ScopeInResponse(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AuthRefreshTokenCookieOnly = false
	})

	_, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)
	insertROPCTestClient(t)

	// Get initial tokens via password grant
	form := url.Values{}
	form.Add("grant_type", "password")
	form.Add("client_id", "ropc-test-client")
	form.Add("username", "testuser")
	form.Add("password", "password123")
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleToken(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	var tokenResp TokenResponse
	err = json.Unmarshal(rr.Body.Bytes(), &tokenResp)
	require.NoError(t, err)
	originalScope := tokenResp.Scope
	require.NotEmpty(t, originalScope, "password grant should return scope")

	// Refresh and assert scope is present in the response
	form2 := url.Values{}
	form2.Add("grant_type", "refresh_token")
	form2.Add("refresh_token", tokenResp.RefreshToken)
	req2 := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr2 := httptest.NewRecorder()
	HandleToken(rr2, req2)
	require.Equal(t, http.StatusOK, rr2.Code)

	var refreshResp TokenResponse
	err = json.Unmarshal(rr2.Body.Bytes(), &refreshResp)
	require.NoError(t, err)
	assert.NotEmpty(t, refreshResp.Scope, "RFC 6749 §5.1: scope must be present in refresh_token grant response")
	assert.Equal(t, originalScope, refreshResp.Scope, "scope must match the original grant scope")
}

func TestHandleToken_RefreshTokenGrant_MissingToken(t *testing.T) {
	testutils.WithTestDB(t)

	form := url.Values{}
	form.Add("grant_type", "refresh_token")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleToken(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_grant")
}

func TestHandleToken_RefreshTokenGrant_InvalidToken(t *testing.T) {
	testutils.WithTestDB(t)

	form := url.Values{}
	form.Add("grant_type", "refresh_token")
	form.Add("refresh_token", "invalid-refresh-token")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleToken(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_grant")
}

func TestHandleToken_RefreshTokenGrant_SessionNotFound(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AuthRefreshTokenCookieOnly = false
	})

	_, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)
	insertROPCTestClient(t)

	// Get tokens via password grant
	form := url.Values{}
	form.Add("grant_type", "password")
	form.Add("client_id", "ropc-test-client")
	form.Add("username", "testuser")
	form.Add("password", "password123")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleToken(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	var tokenResp TokenResponse
	err = json.Unmarshal(rr.Body.Bytes(), &tokenResp)
	assert.NoError(t, err)

	// Delete the session so refresh fails
	_, err = db.GetDB().Exec(`DELETE FROM sessions WHERE access_token = ?`, tokenResp.AccessToken)
	assert.NoError(t, err)

	// Try to refresh
	form2 := url.Values{}
	form2.Add("grant_type", "refresh_token")
	form2.Add("refresh_token", tokenResp.RefreshToken)

	req2 := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr2 := httptest.NewRecorder()

	HandleToken(rr2, req2)

	assert.Equal(t, http.StatusBadRequest, rr2.Code)
	assert.Contains(t, rr2.Body.String(), "invalid_grant")
}

func TestHandleToken_WithSecureCookie(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AuthRefreshTokenCookieOnly = true
		config.Bootstrap.AuthRefreshTokenCookieName = "autentico_refresh_token"
	})

	_, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)
	insertROPCTestClient(t)

	form := url.Values{}
	form.Add("grant_type", "password")
	form.Add("client_id", "ropc-test-client")
	form.Add("username", "testuser")
	form.Add("password", "password123")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleToken(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	// refresh_token should not be in JSON body
	var tokenResp TokenResponse
	err = json.Unmarshal(rr.Body.Bytes(), &tokenResp)
	assert.NoError(t, err)
	assert.Empty(t, tokenResp.RefreshToken)

	// Should be in cookie instead
	cookies := rr.Result().Cookies()
	var refreshCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "autentico_refresh_token" {
			refreshCookie = c
			break
		}
	}
	assert.NotNil(t, refreshCookie)
	assert.True(t, refreshCookie.HttpOnly)
}

func TestHandleToken_WithBasicAuth(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AuthRefreshTokenCookieOnly = false
	})

	_, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	form := url.Values{}
	form.Add("grant_type", "password")
	form.Add("username", "testuser")
	form.Add("password", "password123")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("some-client", "some-secret")
	rr := httptest.NewRecorder()

	HandleToken(rr, req)

	// Should fail because client doesn't exist
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_client")
}

func TestHandleToken_PasswordGrant_InvalidScope(t *testing.T) {
	testutils.WithTestDB(t)

	_, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	_, err = db.GetDB().Exec(`
		INSERT INTO clients (id, client_id, client_name, client_type, redirect_uris, scopes, grant_types, is_active)
		VALUES ('id-scoped', 'scoped-client', 'Scoped Client', 'public', '["http://localhost/callback"]', 'openid profile', '["password","refresh_token"]', TRUE)
	`)
	assert.NoError(t, err)

	form := url.Values{}
	form.Add("grant_type", "password")
	form.Add("client_id", "scoped-client")
	form.Add("username", "testuser")
	form.Add("password", "password123")
	form.Add("scope", "offline_access") // not allowed for this client

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleToken(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_scope")
}

func TestHandleToken_PasswordGrant_DefaultsToClientScopes(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AuthRefreshTokenCookieOnly = false
	})

	_, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	_, err = db.GetDB().Exec(`
		INSERT INTO clients (id, client_id, client_name, client_type, redirect_uris, scopes, grant_types, is_active)
		VALUES ('id-scoped2', 'scoped-client2', 'Scoped Client 2', 'public', '["http://localhost/callback"]', 'openid profile', '["password","refresh_token"]', TRUE)
	`)
	assert.NoError(t, err)

	// No scope requested — should default to the client's configured scopes
	form := url.Values{}
	form.Add("grant_type", "password")
	form.Add("client_id", "scoped-client2")
	form.Add("username", "testuser")
	form.Add("password", "password123")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleToken(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var tokenResp TokenResponse
	err = json.Unmarshal(rr.Body.Bytes(), &tokenResp)
	assert.NoError(t, err)
	assert.Equal(t, "openid profile", tokenResp.Scope)
}

func TestHandleToken_PasswordGrant_AllowedScope(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AuthRefreshTokenCookieOnly = false
	})

	_, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	_, err = db.GetDB().Exec(`
		INSERT INTO clients (id, client_id, client_name, client_type, redirect_uris, scopes, grant_types, is_active)
		VALUES ('id-scoped3', 'scoped-client3', 'Scoped Client 3', 'public', '["http://localhost/callback"]', 'openid profile', '["password","refresh_token"]', TRUE)
	`)
	assert.NoError(t, err)

	form := url.Values{}
	form.Add("grant_type", "password")
	form.Add("client_id", "scoped-client3")
	form.Add("username", "testuser")
	form.Add("password", "password123")
	form.Add("scope", "openid") // subset of allowed scopes

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleToken(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var tokenResp TokenResponse
	err = json.Unmarshal(rr.Body.Bytes(), &tokenResp)
	assert.NoError(t, err)
	assert.Equal(t, "openid", tokenResp.Scope)
}

func TestHandleToken_WithRegisteredClient_DisallowedGrantType(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AuthRefreshTokenCookieOnly = false
	})

	_, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	// Create a client that only allows authorization_code
	_, err = db.GetDB().Exec(`
		INSERT INTO clients (id, client_id, client_secret, client_name, client_type, redirect_uris, grant_types, is_active)
		VALUES ('id-1', 'restricted-client', '', 'Test', 'public', '["http://localhost/callback"]', '["authorization_code"]', TRUE)
	`)
	assert.NoError(t, err)

	form := url.Values{}
	form.Add("grant_type", "password")
	form.Add("client_id", "restricted-client")
	form.Add("username", "testuser")
	form.Add("password", "password123")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleToken(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "unauthorized_client")
}

func TestValidateTokenRequestAuthorizationCode_Valid(t *testing.T) {
	err := ValidateTokenRequestAuthorizationCode(TokenRequest{
		GrantType:   "authorization_code",
		Code:        "some-code",
		RedirectURI: "http://localhost/callback",
	})
	assert.NoError(t, err)
}

func TestValidateTokenRequestAuthorizationCode_MissingCode(t *testing.T) {
	err := ValidateTokenRequestAuthorizationCode(TokenRequest{
		GrantType:   "authorization_code",
		RedirectURI: "http://localhost/callback",
	})
	assert.Error(t, err)
}

func TestValidateTokenRequestAuthorizationCode_MissingRedirect(t *testing.T) {
	err := ValidateTokenRequestAuthorizationCode(TokenRequest{
		GrantType: "authorization_code",
		Code:      "some-code",
	})
	assert.Error(t, err)
}

func TestValidateTokenRequestRefresh_Valid(t *testing.T) {
	err := ValidateTokenRequestRefresh(TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: "some-token",
	})
	assert.NoError(t, err)
}

func TestValidateTokenRequestRefresh_MissingToken(t *testing.T) {
	err := ValidateTokenRequestRefresh(TokenRequest{
		GrantType: "refresh_token",
	})
	assert.Error(t, err)
}

func TestSetRefreshTokenCookie(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AuthRefreshTokenCookieName = "autentico_refresh_token"
		config.Values.AuthRefreshTokenExpiration = 24 * time.Hour
	})

	rr := httptest.NewRecorder()
	SetRefreshTokenCookie(rr, "test-refresh-token")

	cookies := rr.Result().Cookies()
	var cookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "autentico_refresh_token" {
			cookie = c
			break
		}
	}
	assert.NotNil(t, cookie)
	assert.Equal(t, "test-refresh-token", cookie.Value)
	assert.True(t, cookie.HttpOnly)
	assert.True(t, cookie.Secure)
	assert.Equal(t, http.SameSiteStrictMode, cookie.SameSite)
}

func TestHandleToken_RefreshTokenGrant_ExpiredRefreshToken(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AuthRefreshTokenCookieOnly = false
		config.Values.AuthRefreshTokenExpiration = 1 * time.Second
	})

	_, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)
	insertROPCTestClient(t)

	// Get tokens with short-lived refresh token
	form := url.Values{}
	form.Add("grant_type", "password")
	form.Add("client_id", "ropc-test-client")
	form.Add("username", "testuser")
	form.Add("password", "password123")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleToken(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	var tokenResp TokenResponse
	err = json.Unmarshal(rr.Body.Bytes(), &tokenResp)
	assert.NoError(t, err)

	// Wait for refresh token to expire
	time.Sleep(2 * time.Second)

	// Attempt refresh with expired refresh token
	form2 := url.Values{}
	form2.Add("grant_type", "refresh_token")
	form2.Add("refresh_token", tokenResp.RefreshToken)

	req2 := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr2 := httptest.NewRecorder()

	HandleToken(rr2, req2)

	assert.Equal(t, http.StatusBadRequest, rr2.Code)
	assert.Contains(t, rr2.Body.String(), "invalid_grant")
}

func TestUserByRefreshToken_SessionNotFound(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AuthRefreshTokenCookieOnly = false
	})

	usrResp, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	usr := user.User{
		ID:       usrResp.ID,
		Username: usrResp.Username,
		Email:    usrResp.Email,
	}

	// Generate tokens to get a valid refresh token (session won't exist in DB)
	authToken, err := GenerateTokens(usr, "", "openid profile email", config.Get())
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	_, err = UserByRefreshToken(rr, TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: authToken.RefreshToken,
	})
	assert.Error(t, err)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleToken_AuthorizationCodeGrant_ReturnsIDToken(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AuthRefreshTokenCookieOnly = false
	})

	usr, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	// Create auth code with openid scope and nonce
	code := authcode.AuthCode{
		Code:        "test-auth-code-idtoken",
		UserID:      usr.ID,
		ClientID:    "",
		RedirectURI: "http://localhost/callback",
		Scope:       "openid profile email",
		Nonce:       "test-nonce-xyz",
		ExpiresAt:   time.Now().Add(10 * time.Minute),
		Used:        false,
	}
	err = authcode.CreateAuthCode(code)
	assert.NoError(t, err)

	form := url.Values{}
	form.Add("grant_type", "authorization_code")
	form.Add("code", "test-auth-code-idtoken")
	form.Add("redirect_uri", "http://localhost/callback")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleToken(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var tokenResp TokenResponse
	err = json.Unmarshal(rr.Body.Bytes(), &tokenResp)
	assert.NoError(t, err)

	assert.NotEmpty(t, tokenResp.AccessToken)
	assert.NotEmpty(t, tokenResp.IDToken, "id_token should be present when openid scope is requested")
	assert.Equal(t, "openid profile email", tokenResp.Scope)
}

func TestHandleToken_AuthorizationCodeGrant_NoIDTokenWithoutOpenidScope(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AuthRefreshTokenCookieOnly = false
	})

	usr, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	// Create auth code WITHOUT openid scope
	code := authcode.AuthCode{
		Code:        "test-auth-code-no-openid",
		UserID:      usr.ID,
		ClientID:    "",
		RedirectURI: "http://localhost/callback",
		Scope:       "read write",
		ExpiresAt:   time.Now().Add(10 * time.Minute),
		Used:        false,
	}
	err = authcode.CreateAuthCode(code)
	assert.NoError(t, err)

	form := url.Values{}
	form.Add("grant_type", "authorization_code")
	form.Add("code", "test-auth-code-no-openid")
	form.Add("redirect_uri", "http://localhost/callback")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleToken(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var tokenResp TokenResponse
	err = json.Unmarshal(rr.Body.Bytes(), &tokenResp)
	assert.NoError(t, err)

	assert.NotEmpty(t, tokenResp.AccessToken)
	assert.Empty(t, tokenResp.IDToken, "id_token should NOT be present without openid scope")
}

func TestHandleToken_PasswordGrant_ReturnsIDToken(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AuthRefreshTokenCookieOnly = false
	})

	_, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)
	insertROPCTestClient(t)

	form := url.Values{}
	form.Add("grant_type", "password")
	form.Add("client_id", "ropc-test-client")
	form.Add("username", "testuser")
	form.Add("password", "password123")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleToken(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var tokenResp TokenResponse
	err = json.Unmarshal(rr.Body.Bytes(), &tokenResp)
	assert.NoError(t, err)

	// Password grant defaults to "openid profile email" scope, so id_token should be present
	assert.NotEmpty(t, tokenResp.IDToken, "id_token should be present for password grant")
}

// RFC 7636 §4.6: S256 — BASE64URL-ENCODE(SHA256(ASCII(code_verifier))) == code_challenge
// Test vector from RFC 7636 Appendix B
func TestVerifyCodeChallenge_S256(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	assert.True(t, verifyCodeChallenge(challenge, "S256", verifier))
	assert.False(t, verifyCodeChallenge(challenge, "S256", "wrong-verifier"))
}

// RFC 7636 §4.6: plain — code_verifier == code_challenge (direct comparison)
func TestVerifyCodeChallenge_Plain(t *testing.T) {
	verifier := "my-plain-verifier"
	challenge := "my-plain-verifier"

	assert.True(t, verifyCodeChallenge(challenge, "plain", verifier))
	assert.False(t, verifyCodeChallenge(challenge, "plain", "wrong"))
}

// RFC 7636 §4.2: S256 is MTI — empty method defaults to S256
func TestVerifyCodeChallenge_DefaultsToS256(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	assert.True(t, verifyCodeChallenge(challenge, "", verifier))
}

// RFC 7636 §4.4.1: unsupported transformation method MUST be rejected
func TestVerifyCodeChallenge_UnsupportedMethod(t *testing.T) {
	assert.False(t, verifyCodeChallenge("challenge", "unsupported", "verifier"))
}

func pkceS256Challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func TestHandleToken_AuthorizationCodeGrant_PKCE_S256_Success(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AuthRefreshTokenCookieOnly = false
	})

	usr, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := pkceS256Challenge(verifier)

	code := authcode.AuthCode{
		Code:                "pkce-test-code",
		UserID:              usr.ID,
		RedirectURI:         "http://localhost/callback",
		Scope:               "openid",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(10 * time.Minute),
		Used:                false,
	}
	err = authcode.CreateAuthCode(code)
	assert.NoError(t, err)

	form := url.Values{}
	form.Add("grant_type", "authorization_code")
	form.Add("code", "pkce-test-code")
	form.Add("redirect_uri", "http://localhost/callback")
	form.Add("code_verifier", verifier)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleToken(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "access_token")
}

func TestHandleToken_AuthorizationCodeGrant_PKCE_MissingVerifier(t *testing.T) {
	testutils.WithTestDB(t)

	usr, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	code := authcode.AuthCode{
		Code:                "pkce-missing-verifier",
		UserID:              usr.ID,
		RedirectURI:         "http://localhost/callback",
		Scope:               "openid",
		CodeChallenge:       "some-challenge",
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(10 * time.Minute),
		Used:                false,
	}
	err = authcode.CreateAuthCode(code)
	assert.NoError(t, err)

	form := url.Values{}
	form.Add("grant_type", "authorization_code")
	form.Add("code", "pkce-missing-verifier")
	form.Add("redirect_uri", "http://localhost/callback")
	// No code_verifier!

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleToken(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "code_verifier is required")
}

func TestHandleToken_AuthorizationCodeGrant_PKCE_WrongVerifier(t *testing.T) {
	testutils.WithTestDB(t)

	usr, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	verifier := "correct-verifier-value-here-1234567890abcdef"
	challenge := pkceS256Challenge(verifier)

	code := authcode.AuthCode{
		Code:                "pkce-wrong-verifier",
		UserID:              usr.ID,
		RedirectURI:         "http://localhost/callback",
		Scope:               "openid",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(10 * time.Minute),
		Used:                false,
	}
	err = authcode.CreateAuthCode(code)
	assert.NoError(t, err)

	form := url.Values{}
	form.Add("grant_type", "authorization_code")
	form.Add("code", "pkce-wrong-verifier")
	form.Add("redirect_uri", "http://localhost/callback")
	form.Add("code_verifier", "wrong-verifier-value-padded-to-43-chars-abcde")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleToken(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "PKCE verification failed")
}

func TestHandleToken_AuthorizationCodeGrant_NoPKCE_StillWorks(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AuthRefreshTokenCookieOnly = false
	})

	usr, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	// Auth code without PKCE should still work
	code := authcode.AuthCode{
		Code:        "no-pkce-code",
		UserID:      usr.ID,
		RedirectURI: "http://localhost/callback",
		Scope:       "read write",
		ExpiresAt:   time.Now().Add(10 * time.Minute),
		Used:        false,
	}
	err = authcode.CreateAuthCode(code)
	assert.NoError(t, err)

	form := url.Values{}
	form.Add("grant_type", "authorization_code")
	form.Add("code", "no-pkce-code")
	form.Add("redirect_uri", "http://localhost/callback")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleToken(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "access_token")
}

// TestHandleToken_CacheControlHeaders verifies that the token endpoint sets
// Cache-Control: no-store and Pragma: no-cache per RFC 6749 §5.1.
func TestHandleToken_CacheControlHeaders(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AuthRefreshTokenCookieOnly = false
	})

	_, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)
	insertROPCTestClient(t)

	form := url.Values{}
	form.Add("grant_type", "password")
	form.Add("client_id", "ropc-test-client")
	form.Add("username", "testuser")
	form.Add("password", "password123")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleToken(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", rr.Header().Get("Pragma"))
}

// TestHandleToken_RefreshTokenGrant_ClientMismatch verifies that a refresh token
// issued to one client is rejected when presented by a different client
// per RFC 6749 §10.4.
func TestHandleToken_RefreshTokenGrant_ClientMismatch(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AuthRefreshTokenCookieOnly = false
	})

	_, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)
	insertROPCTestClient(t)

	// Insert a second client
	_, err = db.GetDB().Exec(`
		INSERT INTO clients (id, client_id, client_name, client_type, redirect_uris, grant_types, is_active)
		VALUES ('other-client-id', 'other-client', 'Other Client', 'public', '[]', '["password","refresh_token"]', TRUE)
	`)
	assert.NoError(t, err)

	// Obtain a refresh token issued to ropc-test-client
	form := url.Values{}
	form.Add("grant_type", "password")
	form.Add("client_id", "ropc-test-client")
	form.Add("username", "testuser")
	form.Add("password", "password123")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleToken(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	var tokenResp TokenResponse
	err = json.Unmarshal(rr.Body.Bytes(), &tokenResp)
	assert.NoError(t, err)

	// Present the refresh token as other-client — must be rejected
	form2 := url.Values{}
	form2.Add("grant_type", "refresh_token")
	form2.Add("refresh_token", tokenResp.RefreshToken)
	form2.Add("client_id", "other-client")

	req2 := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr2 := httptest.NewRecorder()
	HandleToken(rr2, req2)

	assert.Equal(t, http.StatusBadRequest, rr2.Code)
	assert.Contains(t, rr2.Body.String(), "invalid_grant")
}
