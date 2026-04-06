package token

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/key"
	testutils "github.com/eugenioenko/autentico/tests/utils"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// insertConfidentialClient seeds a confidential OAuth2 client with client_credentials grant.
func insertConfidentialClient(t *testing.T, clientID, secret string, grantTypes string) {
	t.Helper()
	hashed, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	require.NoError(t, err)
	_, err = db.GetDB().Exec(`
		INSERT INTO clients (id, client_id, client_name, client_type, client_secret, redirect_uris, grant_types, scopes, token_endpoint_auth_method, is_active)
		VALUES (?, ?, 'CC Test Client', 'confidential', ?, '[]', ?, 'read write openid profile', 'client_secret_basic', TRUE)
	`, "id-"+clientID, clientID, string(hashed), grantTypes)
	require.NoError(t, err)
}

func TestHandleToken_ClientCredentials_Success(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAccessTokenExpiration = 15 * time.Minute
	})

	insertConfidentialClient(t, "cc-client", "cc-secret", `["client_credentials"]`)

	form := url.Values{}
	form.Add("grant_type", "client_credentials")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("cc-client", "cc-secret")
	rr := httptest.NewRecorder()

	HandleToken(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp TokenResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)

	// RFC 6749 §4.4.3: access_token and token_type MUST be present
	assert.NotEmpty(t, resp.AccessToken)
	assert.Equal(t, "Bearer", resp.TokenType)
	assert.Greater(t, resp.ExpiresIn, 0)

	// RFC 6749 §4.4.3: refresh token SHOULD NOT be included
	assert.Empty(t, resp.RefreshToken)

	// No ID token — no user identity
	assert.Empty(t, resp.IDToken)

	// Verify sub claim is the client_id
	parsed, err := jwt.Parse(resp.AccessToken, func(token *jwt.Token) (interface{}, error) {
		return key.GetPublicKey(), nil
	})
	require.NoError(t, err)
	claims := parsed.Claims.(jwt.MapClaims)
	assert.Equal(t, "cc-client", claims["sub"])
	assert.Equal(t, "cc-client", claims["azp"])

	// RFC 6749 §5.1: Cache-Control and Pragma headers
	assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", rr.Header().Get("Pragma"))

	// openid should be stripped from scope
	assert.NotContains(t, resp.Scope, "openid")
}

func TestHandleToken_ClientCredentials_NoClientAuth(t *testing.T) {
	testutils.WithTestDB(t)

	form := url.Values{}
	form.Add("grant_type", "client_credentials")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleToken(rr, req)

	// RFC 6749 §4.4.2: client MUST authenticate
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_client")
}

func TestHandleToken_ClientCredentials_PublicClient(t *testing.T) {
	testutils.WithTestDB(t)

	// Insert a public client with client_credentials grant
	_, err := db.GetDB().Exec(`
		INSERT INTO clients (id, client_id, client_name, client_type, redirect_uris, grant_types, scopes, is_active)
		VALUES ('id-pub', 'pub-client', 'Public Client', 'public', '[]', '["client_credentials"]', 'read write', TRUE)
	`)
	require.NoError(t, err)

	form := url.Values{}
	form.Add("grant_type", "client_credentials")
	form.Add("client_id", "pub-client")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleToken(rr, req)

	// RFC 6749 §4.4.2: only confidential clients may use client_credentials
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "unauthorized_client")
}

func TestHandleToken_ClientCredentials_GrantNotAllowed(t *testing.T) {
	testutils.WithTestDB(t)

	// Client with only authorization_code grant
	insertConfidentialClient(t, "no-cc-client", "secret", `["authorization_code"]`)

	form := url.Values{}
	form.Add("grant_type", "client_credentials")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("no-cc-client", "secret")
	rr := httptest.NewRecorder()

	HandleToken(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "unauthorized_client")
}

func TestHandleToken_ClientCredentials_InvalidScope(t *testing.T) {
	testutils.WithTestDB(t)

	insertConfidentialClient(t, "cc-scope-client", "secret", `["client_credentials"]`)

	form := url.Values{}
	form.Add("grant_type", "client_credentials")
	form.Add("scope", "admin superuser")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("cc-scope-client", "secret")
	rr := httptest.NewRecorder()

	HandleToken(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_scope")
}

func TestHandleToken_ClientCredentials_OpenIDScopeStripped(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAccessTokenExpiration = 15 * time.Minute
	})

	insertConfidentialClient(t, "cc-openid-client", "secret", `["client_credentials"]`)

	form := url.Values{}
	form.Add("grant_type", "client_credentials")
	form.Add("scope", "openid read write")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("cc-openid-client", "secret")
	rr := httptest.NewRecorder()

	HandleToken(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp TokenResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)

	// openid must be stripped — no user identity to assert
	assert.NotContains(t, resp.Scope, "openid")
	assert.Contains(t, resp.Scope, "read")
	assert.Contains(t, resp.Scope, "write")
}

func TestHandleToken_ClientCredentials_WithExplicitScope(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAccessTokenExpiration = 15 * time.Minute
	})

	insertConfidentialClient(t, "cc-explicit-scope", "secret", `["client_credentials"]`)

	form := url.Values{}
	form.Add("grant_type", "client_credentials")
	form.Add("scope", "read")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("cc-explicit-scope", "secret")
	rr := httptest.NewRecorder()

	HandleToken(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp TokenResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "read", resp.Scope)
}

func TestGenerateClientCredentialsToken(t *testing.T) {
	config.Values.AuthAccessTokenExpiration = 15 * time.Minute
	config.Bootstrap.AppAuthIssuer = "http://localhost/oauth2"

	token, err := GenerateClientCredentialsToken("test-client", "read write", config.Get())
	require.NoError(t, err)

	assert.NotEmpty(t, token.AccessToken)
	assert.Empty(t, token.RefreshToken)
	assert.Empty(t, token.UserID)
	assert.WithinDuration(t, time.Now().Add(15*time.Minute), token.AccessExpiresAt, time.Minute)

	// Verify JWT claims
	parsed, err := jwt.Parse(token.AccessToken, func(t *jwt.Token) (interface{}, error) {
		return key.GetPublicKey(), nil
	})
	require.NoError(t, err)
	claims := parsed.Claims.(jwt.MapClaims)

	assert.Equal(t, "test-client", claims["sub"])
	assert.Equal(t, "test-client", claims["azp"])
	assert.Equal(t, "Bearer", claims["typ"])
	assert.Equal(t, "read write", claims["scope"])
	assert.Equal(t, "http://localhost/oauth2", claims["iss"])
}

func TestRemoveScope(t *testing.T) {
	assert.Equal(t, "read write", removeScope("openid read write", "openid"))
	assert.Equal(t, "openid write", removeScope("openid read write", "read"))
	assert.Equal(t, "read write", removeScope("read write", "openid"))
	assert.Equal(t, "", removeScope("openid", "openid"))
	assert.Equal(t, "", removeScope("", "openid"))
}
