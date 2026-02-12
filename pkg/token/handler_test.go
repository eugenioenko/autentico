package token

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
)

func TestHandleToken(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthRefreshTokenAsSecureCookie = false
	})

	// Create a test user
	_, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	// Perform token request
	form := url.Values{}
	form.Add("grant_type", "password")
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

	form := url.Values{}
	form.Add("grant_type", "password")
	form.Add("username", "testuser")
	form.Add("password", "wrongpassword")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleToken(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
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
		config.Values.AuthRefreshTokenAsSecureCookie = false
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
		config.Values.AuthRefreshTokenAsSecureCookie = false
	})

	// Create user and get tokens via password grant
	_, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	form := url.Values{}
	form.Add("grant_type", "password")
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

func TestHandleToken_RefreshTokenGrant_MissingToken(t *testing.T) {
	testutils.WithTestDB(t)

	form := url.Values{}
	form.Add("grant_type", "refresh_token")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleToken(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
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

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_grant")
}

func TestHandleToken_RefreshTokenGrant_SessionNotFound(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthRefreshTokenAsSecureCookie = false
	})

	_, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	// Get tokens via password grant
	form := url.Values{}
	form.Add("grant_type", "password")
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

	assert.Equal(t, http.StatusUnauthorized, rr2.Code)
	assert.Contains(t, rr2.Body.String(), "invalid_grant")
}

func TestHandleToken_WithSecureCookie(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthRefreshTokenAsSecureCookie = true
		config.Values.AuthRefreshTokenCookieName = "autentico_refresh_token"
	})

	_, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	form := url.Values{}
	form.Add("grant_type", "password")
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
		config.Values.AuthRefreshTokenAsSecureCookie = false
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

func TestHandleToken_WithRegisteredClient_DisallowedGrantType(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthRefreshTokenAsSecureCookie = false
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

func TestSetRefreshTokenAsSecureCookie(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthRefreshTokenCookieName = "autentico_refresh_token"
		config.Values.AuthRefreshTokenExpiration = 24 * time.Hour
	})

	rr := httptest.NewRecorder()
	SetRefreshTokenAsSecureCookie(rr, "test-refresh-token")

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

func TestHandleRevoke_NonPostMethod(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/revoke", nil)
	rr := httptest.NewRecorder()

	HandleRevoke(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Only POST method is allowed")
}

func TestHandleRevoke_MissingToken(t *testing.T) {
	testutils.WithTestDB(t)

	form := url.Values{}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleRevoke(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Token is required")
}

func TestHandleRevoke_InvalidToken(t *testing.T) {
	testutils.WithTestDB(t)

	form := url.Values{}
	form.Add("token", "invalid-token")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleRevoke(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_token")
}

func TestHandleRevoke_ValidToken(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthRefreshTokenAsSecureCookie = false
	})

	_, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	// Get a token
	form := url.Values{}
	form.Add("grant_type", "password")
	form.Add("username", "testuser")
	form.Add("password", "password123")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleToken(rr, req)

	var tokenResp TokenResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &tokenResp)

	// Revoke it
	form2 := url.Values{}
	form2.Add("token", tokenResp.AccessToken)

	req2 := httptest.NewRequest(http.MethodPost, "/oauth2/revoke", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr2 := httptest.NewRecorder()

	HandleRevoke(rr2, req2)

	assert.Equal(t, http.StatusOK, rr2.Code)

	// Verify revoked_at is set
	var revokedAt string
	err = db.GetDB().QueryRow(fmt.Sprintf(`SELECT revoked_at FROM tokens WHERE access_token = '%s'`, tokenResp.AccessToken)).Scan(&revokedAt)
	assert.NoError(t, err)
	assert.NotEmpty(t, revokedAt)
}

func TestHandleToken_RefreshTokenGrant_ExpiredRefreshToken(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthRefreshTokenAsSecureCookie = false
		config.Values.AuthRefreshTokenExpiration = 1 * time.Second
	})

	_, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	// Get tokens with short-lived refresh token
	form := url.Values{}
	form.Add("grant_type", "password")
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

	assert.Equal(t, http.StatusUnauthorized, rr2.Code)
	assert.Contains(t, rr2.Body.String(), "invalid_grant")
}

func TestUserByRefreshToken_SessionNotFound(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthRefreshTokenAsSecureCookie = false
	})

	usrResp, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	usr := user.User{
		ID:       usrResp.ID,
		Username: usrResp.Username,
		Email:    usrResp.Email,
	}

	// Generate tokens to get a valid refresh token (session won't exist in DB)
	authToken, err := GenerateTokens(usr)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	_, err = UserByRefreshToken(rr, TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: authToken.RefreshToken,
	})
	assert.Error(t, err)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestHandleToken_AuthorizationCodeGrant_ReturnsIDToken(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthRefreshTokenAsSecureCookie = false
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
		config.Values.AuthRefreshTokenAsSecureCookie = false
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
		config.Values.AuthRefreshTokenAsSecureCookie = false
	})

	_, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	form := url.Values{}
	form.Add("grant_type", "password")
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

func TestVerifyCodeChallenge_S256(t *testing.T) {
	// code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	// SHA256 of that, base64url-encoded = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	// (This is the RFC 7636 example)
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	assert.True(t, verifyCodeChallenge(challenge, "S256", verifier))
	assert.False(t, verifyCodeChallenge(challenge, "S256", "wrong-verifier"))
}

func TestVerifyCodeChallenge_Plain(t *testing.T) {
	verifier := "my-plain-verifier"
	challenge := "my-plain-verifier"

	assert.True(t, verifyCodeChallenge(challenge, "plain", verifier))
	assert.False(t, verifyCodeChallenge(challenge, "plain", "wrong"))
}

func TestVerifyCodeChallenge_DefaultsToS256(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	// Empty method should default to S256
	assert.True(t, verifyCodeChallenge(challenge, "", verifier))
}

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
		config.Values.AuthRefreshTokenAsSecureCookie = false
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
	form.Add("code_verifier", "wrong-verifier-value")

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
		config.Values.AuthRefreshTokenAsSecureCookie = false
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
