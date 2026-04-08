package introspect

import (
	"bytes"
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
	"github.com/rs/xid"
	"github.com/stretchr/testify/assert"
)

const testClientID = "introspect-test-client"
const testClientSecret = "introspect-test-secret"

// setupTestClient creates a confidential client for introspect tests.
func setupTestClient(t *testing.T) {
	t.Helper()
	testutils.InsertTestConfidentialClient(t, testClientID, testClientSecret)
}

// withBasicAuth adds client_secret_basic credentials to a request.
func withBasicAuth(req *http.Request) *http.Request {
	req.SetBasicAuth(testClientID, testClientSecret)
	return req
}

// generateTestTokenAndStore creates a valid JWT access token and stores it in the database for testing
func generateTestTokenAndStore(userID string) (string, string, error) {
	sessionID := xid.New().String()
	tokenID := xid.New().String()
	accessTokenExpiresAt := time.Now().Add(config.Get().AuthAccessTokenExpiration).UTC()
	refreshTokenExpiresAt := time.Now().Add(config.Get().AuthRefreshTokenExpiration).UTC()

	accessClaims := jwt.MapClaims{
		"exp":   accessTokenExpiresAt.Unix(),
		"iat":   time.Now().Unix(),
		"iss":   config.GetBootstrap().AppAuthIssuer,
		"aud":   config.Get().AuthAccessTokenAudience,
		"sub":   userID,
		"typ":   "Bearer",
		"sid":   sessionID,
		"scope": "openid profile email",
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims)
	accessToken.Header["kid"] = config.GetBootstrap().AuthJwkCertKeyID
	signedToken, err := accessToken.SignedString(key.GetPrivateKey())
	if err != nil {
		return "", "", err
	}

	// Store token in database
	_, err = db.GetDB().Exec(`
		INSERT INTO tokens (id, user_id, access_token, refresh_token, access_token_type,
			refresh_token_expires_at, access_token_expires_at, issued_at, scope, grant_type)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, tokenID, userID, signedToken, "refresh-token", "Bearer",
		refreshTokenExpiresAt, accessTokenExpiresAt, time.Now(), "openid profile email", "password")
	if err != nil {
		return "", "", err
	}

	// Store session in database
	_, err = db.GetDB().Exec(`
		INSERT INTO sessions (id, user_id, access_token, refresh_token, user_agent, ip_address, location, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, sessionID, userID, signedToken, "", "", "", "", time.Now(), accessTokenExpiresAt)

	return signedToken, sessionID, err
}

// ---------------------------------------------------------------------------
// RFC 7662 §2.1 — Client authentication (negative tests)
// ---------------------------------------------------------------------------

// TestHandleIntrospect_NoAuth_Returns401 verifies RFC 7662 §2.1:
// "the endpoint MUST also require some form of authorization to access this endpoint"
func TestHandleIntrospect_NoAuth_Returns401(t *testing.T) {
	testutils.WithTestDB(t)

	form := url.Values{}
	form.Set("token", "some-token")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleIntrospect(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code, "RFC 7662 §2.1: unauthenticated request MUST be rejected")
	assert.Contains(t, rr.Body.String(), "invalid_client")
}

// TestHandleIntrospect_InvalidClientCredentials_Returns401 verifies that wrong
// client credentials are rejected with 401.
func TestHandleIntrospect_InvalidClientCredentials_Returns401(t *testing.T) {
	testutils.WithTestDB(t)
	setupTestClient(t)

	form := url.Values{}
	form.Set("token", "some-token")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(testClientID, "wrong-secret")
	rr := httptest.NewRecorder()

	HandleIntrospect(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code, "wrong client secret MUST be rejected")
	assert.Contains(t, rr.Body.String(), "invalid_client")
}

// TestHandleIntrospect_UnknownClient_Returns401 verifies that an unknown
// client_id is rejected with 401.
func TestHandleIntrospect_UnknownClient_Returns401(t *testing.T) {
	testutils.WithTestDB(t)

	form := url.Values{}
	form.Set("token", "some-token")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("nonexistent-client", "some-secret")
	rr := httptest.NewRecorder()

	HandleIntrospect(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code, "unknown client MUST be rejected")
	assert.Contains(t, rr.Body.String(), "invalid_client")
}

// ---------------------------------------------------------------------------
// RFC 7662 §2.1 — Form-encoded requests (with client auth)
// ---------------------------------------------------------------------------

// TestHandleIntrospect_FormEncoded verifies RFC 7662 §2.1:
// "The protected resource calls the introspection endpoint using an HTTP POST
// request with parameters sent as application/x-www-form-urlencoded data."
func TestHandleIntrospect_FormEncoded_InvalidToken_ActiveFalse(t *testing.T) {
	testutils.WithTestDB(t)
	setupTestClient(t)

	form := url.Values{}
	form.Set("token", "some-unknown-token")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	withBasicAuth(req)
	rr := httptest.NewRecorder()

	HandleIntrospect(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code, "RFC 7662 §2.1: form-encoded request must be accepted")
	var resp IntrospectResponse
	assert.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.False(t, resp.Active)
}

func TestHandleIntrospect_FormEncoded_ValidToken_Active(t *testing.T) {
	testutils.WithTestDB(t)
	setupTestClient(t)

	userID := xid.New().String()
	_, err := db.GetDB().Exec(`INSERT INTO users (id, username, email, password) VALUES (?, ?, ?, ?)`,
		userID, "formuser", "form@example.com", "hash")
	assert.NoError(t, err)

	accessToken, _, err := generateTestTokenAndStore(userID)
	assert.NoError(t, err)

	form := url.Values{}
	form.Set("token", accessToken)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	withBasicAuth(req)
	rr := httptest.NewRecorder()

	HandleIntrospect(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp IntrospectResponse
	assert.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.True(t, resp.Active)
	assert.Equal(t, userID, resp.Sub)
}

// ---------------------------------------------------------------------------
// JSON-encoded requests (with client auth)
// ---------------------------------------------------------------------------

func TestHandleIntrospectEmptyBody(t *testing.T) {
	testutils.WithTestDB(t)
	setupTestClient(t)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", nil)
	withBasicAuth(req)
	rr := httptest.NewRecorder()

	HandleIntrospect(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_request")
}

func TestHandleIntrospectInvalidJSON(t *testing.T) {
	testutils.WithTestDB(t)
	setupTestClient(t)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", bytes.NewReader([]byte("invalid json")))
	withBasicAuth(req)
	rr := httptest.NewRecorder()

	HandleIntrospect(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid request payload")
}

func TestHandleIntrospectMissingToken(t *testing.T) {
	testutils.WithTestDB(t)
	setupTestClient(t)

	reqBody := IntrospectRequest{Token: ""}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", bytes.NewReader(body))
	withBasicAuth(req)
	rr := httptest.NewRecorder()

	HandleIntrospect(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Token is required")
}

// TestHandleIntrospectInvalidToken verifies RFC 7662 §2.2:
// "If the token is not active... the authorization server MUST return...
// a JSON object with the 'active' field set to 'false'."
// The response MUST be 200, not 401.
func TestHandleIntrospectInvalidToken(t *testing.T) {
	testutils.WithTestDB(t)
	setupTestClient(t)

	reqBody := IntrospectRequest{Token: "invalid-token"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", bytes.NewReader(body))
	withBasicAuth(req)
	rr := httptest.NewRecorder()

	HandleIntrospect(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code, "RFC 7662 §2.2: invalid token MUST return 200 with active=false")
	var resp IntrospectResponse
	assert.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.False(t, resp.Active)
}

func TestHandleIntrospectValidToken(t *testing.T) {
	testutils.WithTestDB(t)
	setupTestClient(t)

	// Create a test user
	userID := xid.New().String()
	_, err := db.GetDB().Exec(`
		INSERT INTO users (id, username, email, password) VALUES (?, ?, ?, ?)
	`, userID, "introspectuser", "introspect@example.com", "hashedpassword")
	assert.NoError(t, err)

	// Generate and store a token
	accessToken, _, err := generateTestTokenAndStore(userID)
	assert.NoError(t, err)

	reqBody := IntrospectRequest{Token: accessToken}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", bytes.NewReader(body))
	withBasicAuth(req)
	rr := httptest.NewRecorder()

	HandleIntrospect(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var response IntrospectResponse
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.True(t, response.Active)
	assert.Equal(t, userID, response.Sub)
	assert.NotEmpty(t, response.Scope)
}

func TestIntrospectToken(t *testing.T) {
	_, err := db.InitTestDB()
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	// Create a test user
	userID := xid.New().String()
	_, err = db.GetDB().Exec(`
		INSERT INTO users (id, username, email, password) VALUES (?, ?, ?, ?)
	`, userID, "introspectuser2", "introspect2@example.com", "hashedpassword")
	assert.NoError(t, err)

	// Generate and store a token
	accessToken, _, err := generateTestTokenAndStore(userID)
	assert.NoError(t, err)

	// Introspect the token
	token, err := IntrospectToken(accessToken)
	assert.NoError(t, err)
	assert.NotNil(t, token)
	assert.Equal(t, userID, *token.UserID)
	assert.Equal(t, accessToken, token.AccessToken)
}

func TestIntrospectTokenNotFound(t *testing.T) {
	_, err := db.InitTestDB()
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	_, err = IntrospectToken("nonexistent-token")
	assert.Error(t, err)
}

func TestHandleIntrospectNilBody(t *testing.T) {
	testutils.WithTestDB(t)
	setupTestClient(t)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", nil)
	req.Body = nil // explicitly nil body
	withBasicAuth(req)
	rr := httptest.NewRecorder()

	HandleIntrospect(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleIntrospectTokenNotInDB(t *testing.T) {
	testutils.WithTestDB(t)
	setupTestClient(t)

	// Create a valid JWT but don't store it in tokens table
	accessTokenExpiresAt := time.Now().Add(config.Get().AuthAccessTokenExpiration).UTC()
	claims := jwt.MapClaims{
		"exp":   accessTokenExpiresAt.Unix(),
		"iat":   time.Now().Unix(),
		"iss":   config.GetBootstrap().AppAuthIssuer,
		"aud":   config.Get().AuthAccessTokenAudience,
		"sub":   "some-user-id",
		"typ":   "Bearer",
		"sid":   xid.New().String(),
		"scope": "openid",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = config.GetBootstrap().AuthJwkCertKeyID
	signedToken, err := token.SignedString(key.GetPrivateKey())
	assert.NoError(t, err)

	reqBody := IntrospectRequest{Token: signedToken}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", bytes.NewReader(body))
	withBasicAuth(req)
	rr := httptest.NewRecorder()

	HandleIntrospect(rr, req)

	// RFC 7662 §2.2: valid JWT not in DB → 200 {"active":false}
	assert.Equal(t, http.StatusOK, rr.Code, "RFC 7662 §2.2: unknown token MUST return 200 with active=false")
	var resp IntrospectResponse
	assert.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.False(t, resp.Active)
}

func TestHandleIntrospectTokenNoSession(t *testing.T) {
	testutils.WithTestDB(t)
	setupTestClient(t)

	userID := xid.New().String()
	_, err := db.GetDB().Exec(`
		INSERT INTO users (id, username, email, password) VALUES (?, ?, ?, ?)
	`, userID, "nosessuser", "nosess@example.com", "hashedpassword")
	assert.NoError(t, err)

	// Generate and store a token but don't create a session
	tokenID := xid.New().String()
	accessTokenExpiresAt := time.Now().Add(config.Get().AuthAccessTokenExpiration).UTC()
	refreshTokenExpiresAt := time.Now().Add(config.Get().AuthRefreshTokenExpiration).UTC()

	claims := jwt.MapClaims{
		"exp":   accessTokenExpiresAt.Unix(),
		"iat":   time.Now().Unix(),
		"iss":   config.GetBootstrap().AppAuthIssuer,
		"aud":   config.Get().AuthAccessTokenAudience,
		"sub":   userID,
		"typ":   "Bearer",
		"sid":   xid.New().String(),
		"scope": "openid",
	}
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	jwtToken.Header["kid"] = config.GetBootstrap().AuthJwkCertKeyID
	signedToken, err := jwtToken.SignedString(key.GetPrivateKey())
	assert.NoError(t, err)

	// Store token in DB but don't create session
	_, err = db.GetDB().Exec(`
		INSERT INTO tokens (id, user_id, access_token, refresh_token, access_token_type,
			refresh_token_expires_at, access_token_expires_at, issued_at, scope, grant_type)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, tokenID, userID, signedToken, "refresh-token", "Bearer",
		refreshTokenExpiresAt, accessTokenExpiresAt, time.Now(), "openid", "password")
	assert.NoError(t, err)

	reqBody := IntrospectRequest{Token: signedToken}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", bytes.NewReader(body))
	withBasicAuth(req)
	rr := httptest.NewRecorder()

	HandleIntrospect(rr, req)

	// RFC 7662 §2.2: no session → 200 {"active":false}
	assert.Equal(t, http.StatusOK, rr.Code, "RFC 7662 §2.2: token with no session MUST return 200 with active=false")
	var resp IntrospectResponse
	assert.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.False(t, resp.Active)
}

func TestIntrospectTokenRevoked(t *testing.T) {
	_, err := db.InitTestDB()
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	userID := xid.New().String()
	_, err = db.GetDB().Exec(`
		INSERT INTO users (id, username, email, password) VALUES (?, ?, ?, ?)
	`, userID, "revokeduser", "revoked@example.com", "hashedpassword")
	assert.NoError(t, err)

	accessToken, _, err := generateTestTokenAndStore(userID)
	assert.NoError(t, err)

	// Revoke the token
	_, err = db.GetDB().Exec(`UPDATE tokens SET revoked_at = ? WHERE access_token = ?`, time.Now(), accessToken)
	assert.NoError(t, err)

	_, err = IntrospectToken(accessToken)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token has been revoked")
}

func TestValidateTokenIntrospectRequest_Valid(t *testing.T) {
	err := ValidateTokenIntrospectRequest(IntrospectRequest{Token: "some-token"})
	assert.NoError(t, err)
}

func TestValidateTokenIntrospectRequest_Empty(t *testing.T) {
	err := ValidateTokenIntrospectRequest(IntrospectRequest{Token: ""})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token is required")
}

// RFC 7662 §2.2: verify that active token response includes all populated OPTIONAL fields
func TestHandleIntrospect_ActiveToken_AllFields(t *testing.T) {
	testutils.WithTestDB(t)
	setupTestClient(t)

	userID := xid.New().String()
	_, err := db.GetDB().Exec(`INSERT INTO users (id, username, email, password) VALUES (?, ?, ?, ?)`,
		userID, "allfieldsuser", "allfields@example.com", "hash")
	assert.NoError(t, err)

	accessToken, _, err := generateTestTokenAndStore(userID)
	assert.NoError(t, err)

	form := url.Values{}
	form.Set("token", accessToken)
	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	withBasicAuth(req)
	rr := httptest.NewRecorder()

	HandleIntrospect(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp map[string]interface{}
	assert.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))

	// RFC 7662 §2.2: "active" is REQUIRED
	assert.Equal(t, true, resp["active"])
	// OPTIONAL fields that our implementation populates
	assert.NotEmpty(t, resp["scope"], "scope should be populated for active tokens")
	assert.NotEmpty(t, resp["token_type"], "token_type should be populated")
	assert.NotEmpty(t, resp["sub"], "sub should be populated")
	assert.NotEmpty(t, resp["jti"], "jti should be populated")
	assert.NotNil(t, resp["exp"], "exp should be populated")
	assert.NotNil(t, resp["iat"], "iat should be populated")
	assert.NotEmpty(t, resp["iss"], "iss should be populated for active tokens")
}

// RFC 7662 §2.2: inactive token SHOULD NOT include additional information
func TestHandleIntrospect_InactiveToken_NoExtraFields(t *testing.T) {
	testutils.WithTestDB(t)
	setupTestClient(t)

	form := url.Values{}
	form.Set("token", "nonexistent-token")
	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	withBasicAuth(req)
	rr := httptest.NewRecorder()

	HandleIntrospect(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp map[string]interface{}
	assert.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))

	assert.Equal(t, false, resp["active"])
	// RFC 7662 §2.2: SHOULD NOT include extra claims for inactive tokens
	_, hasSub := resp["sub"]
	_, hasScope := resp["scope"]
	assert.False(t, hasSub, "inactive token should not include sub")
	assert.False(t, hasScope, "inactive token should not include scope")
}

// ---------------------------------------------------------------------------
// RFC 7662 §2.1 — Bearer token authentication (RFC 6750 alternative)
// ---------------------------------------------------------------------------

// generateBearerJWT creates a signed JWT for the given userID.
func generateBearerJWT(t *testing.T, userID string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"iss":   config.GetBootstrap().AppAuthIssuer,
		"aud":   config.Get().AuthAccessTokenAudience,
		"sub":   userID,
		"typ":   "Bearer",
		"sid":   xid.New().String(),
		"scope": "openid",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = config.GetBootstrap().AuthJwkCertKeyID
	signed, err := token.SignedString(key.GetPrivateKey())
	assert.NoError(t, err)
	return signed
}

// TestHandleIntrospect_BearerAuth_Admin verifies RFC 7662 §2.1 + §4:
// a valid Bearer token from an admin user is accepted for introspection.
func TestHandleIntrospect_BearerAuth_Admin(t *testing.T) {
	testutils.WithTestDB(t)

	adminID := xid.New().String()
	_, err := db.GetDB().Exec(
		`INSERT INTO users (id, username, email, password, role) VALUES (?, ?, ?, ?, 'admin')`,
		adminID, "introadmin", "introadmin@example.com", "hash")
	assert.NoError(t, err)

	bearerJWT := generateBearerJWT(t, adminID)

	form := url.Values{}
	form.Set("token", "some-unknown-token")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+bearerJWT)
	rr := httptest.NewRecorder()

	HandleIntrospect(rr, req)

	// Auth succeeds, unknown token returns inactive
	assert.Equal(t, http.StatusOK, rr.Code)
	var resp IntrospectResponse
	assert.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.False(t, resp.Active)
}

// TestHandleIntrospect_BearerAuth_NonAdmin verifies RFC 7662 §4:
// a non-admin user's Bearer token is rejected with 403.
func TestHandleIntrospect_BearerAuth_NonAdmin(t *testing.T) {
	testutils.WithTestDB(t)

	userID := xid.New().String()
	_, err := db.GetDB().Exec(
		`INSERT INTO users (id, username, email, password, role) VALUES (?, ?, ?, ?, 'user')`,
		userID, "introuser", "introuser@example.com", "hash")
	assert.NoError(t, err)

	bearerJWT := generateBearerJWT(t, userID)

	form := url.Values{}
	form.Set("token", "some-token")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+bearerJWT)
	rr := httptest.NewRecorder()

	HandleIntrospect(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code, "RFC 7662 §4: non-admin bearer MUST be rejected")
	assert.Contains(t, rr.Body.String(), "insufficient_scope")
}

// TestHandleIntrospect_BearerAuth_Expired verifies that an expired Bearer
// token is rejected with 401.
func TestHandleIntrospect_BearerAuth_Expired(t *testing.T) {
	testutils.WithTestDB(t)

	claims := jwt.MapClaims{
		"exp":   time.Now().Add(-time.Hour).Unix(), // expired
		"iat":   time.Now().Add(-2 * time.Hour).Unix(),
		"iss":   config.GetBootstrap().AppAuthIssuer,
		"aud":   config.Get().AuthAccessTokenAudience,
		"sub":   "bearer-auth-user",
		"typ":   "Bearer",
		"sid":   xid.New().String(),
		"scope": "openid",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = config.GetBootstrap().AuthJwkCertKeyID
	expiredJWT, err := token.SignedString(key.GetPrivateKey())
	assert.NoError(t, err)

	form := url.Values{}
	form.Set("token", "some-token")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+expiredJWT)
	rr := httptest.NewRecorder()

	HandleIntrospect(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_token")
}

// TestHandleIntrospect_BearerAuth_Invalid verifies that a malformed Bearer
// token is rejected with 401.
func TestHandleIntrospect_BearerAuth_Invalid(t *testing.T) {
	testutils.WithTestDB(t)

	form := url.Values{}
	form.Set("token", "some-token")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer not-a-valid-jwt")
	rr := httptest.NewRecorder()

	HandleIntrospect(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_token")
}

// TestHandleIntrospect_ClientSecretPost verifies that client_secret_post
// authentication works for the introspect endpoint (RFC 7662 §2.1).
func TestHandleIntrospect_ClientSecretPost(t *testing.T) {
	testutils.WithTestDB(t)
	setupTestClient(t)

	form := url.Values{}
	form.Set("token", "some-unknown-token")
	form.Set("client_id", testClientID)
	form.Set("client_secret", testClientSecret)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleIntrospect(rr, req)

	// Should authenticate successfully and return inactive for unknown token
	assert.Equal(t, http.StatusOK, rr.Code)
	var resp IntrospectResponse
	assert.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.False(t, resp.Active)
}
