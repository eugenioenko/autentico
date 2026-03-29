package userinfo

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/key"
	"github.com/eugenioenko/autentico/pkg/jwtutil"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/rs/xid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestTokens creates a valid JWT access token and stores it in the database for testing
func generateTestTokens(userID string) (string, error) {
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
		return "", err
	}

	// Store token in database for introspection
	_, err = db.GetDB().Exec(`
		INSERT INTO tokens (id, user_id, access_token, refresh_token, access_token_type,
			refresh_token_expires_at, access_token_expires_at, issued_at, scope, grant_type)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, tokenID, userID, signedToken, "refresh-token", "Bearer",
		refreshTokenExpiresAt, accessTokenExpiresAt, time.Now(), "openid profile email", "password")
	if err != nil {
		return "", err
	}

	// Create session so the session deactivation check passes
	_, err = db.GetDB().Exec(`
		INSERT INTO sessions (id, user_id, access_token, refresh_token, user_agent, ip_address, location, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, sessionID, userID, signedToken, "", "", "", "", time.Now(), accessTokenExpiresAt)

	return signedToken, err
}

func TestHandleUserInfo(t *testing.T) {
	testutils.WithTestDB(t)

	// Create a test user directly in the database
	userID := xid.New().String()
	_, err := db.GetDB().Exec(`
		INSERT INTO users (id, username, email, password) VALUES (?, ?, ?, ?)
	`, userID, "testuser", "testuser@example.com", "hashedpassword")
	assert.NoError(t, err)

	// Generate a real JWT token and store it
	accessToken, err := generateTestTokens(userID)
	assert.NoError(t, err)

	// Perform user info request
	req := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rr := httptest.NewRecorder()

	HandleUserInfo(rr, req)

	// Verify the response
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "testuser@example.com")
	assert.Contains(t, rr.Body.String(), "testuser")
}

func TestHandleUserInfoMissingAuth(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	rr := httptest.NewRecorder()

	HandleUserInfo(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Header().Get("WWW-Authenticate"), "Bearer", "RFC 6750 §3: WWW-Authenticate must be set")
}

func TestHandleUserInfoInvalidToken(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	rr := httptest.NewRecorder()

	HandleUserInfo(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestHandleUserInfoInvalidAuthFormat(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rr := httptest.NewRecorder()

	HandleUserInfo(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Header().Get("WWW-Authenticate"), "Bearer", "RFC 6750 §3: WWW-Authenticate must be set")
}

func TestHandleUserInfoTokenNotInDB(t *testing.T) {
	testutils.WithTestDB(t)

	// Generate a valid JWT but don't store it in the tokens table
	userID := xid.New().String()
	_, err := db.GetDB().Exec(`
		INSERT INTO users (id, username, email, password) VALUES (?, ?, ?, ?)
	`, userID, "testuser", "test@example.com", "hashedpassword")
	assert.NoError(t, err)

	accessTokenExpiresAt := time.Now().Add(config.Get().AuthAccessTokenExpiration).UTC()
	accessClaims := jwt.MapClaims{
		"exp":   accessTokenExpiresAt.Unix(),
		"iat":   time.Now().Unix(),
		"iss":   config.GetBootstrap().AppAuthIssuer,
		"aud":   config.Get().AuthAccessTokenAudience,
		"sub":   userID,
		"typ":   "Bearer",
		"sid":   xid.New().String(),
		"scope": "openid profile email",
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims)
	accessToken.Header["kid"] = config.GetBootstrap().AuthJwkCertKeyID
	signedToken, err := accessToken.SignedString(key.GetPrivateKey())
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+signedToken)
	rr := httptest.NewRecorder()

	HandleUserInfo(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid or expired token")
}

func TestHandleUserInfo_DeactivatedSession(t *testing.T) {
	testutils.WithTestDB(t)

	userID := xid.New().String()
	_, _ = db.GetDB().Exec(`
		INSERT INTO users (id, username, email, password) VALUES (?, ?, ?, ?)
	`, userID, "testuser", "test@example.com", "hashedpassword")

	accessToken, _ := generateTestTokens(userID)

	// Deactivate the session
	_, _ = db.GetDB().Exec("UPDATE sessions SET deactivated_at = CURRENT_TIMESTAMP")

	req := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rr := httptest.NewRecorder()

	HandleUserInfo(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "Session has been deactivated")
}

// generateTestTokensWithScope is like generateTestTokens but with a custom scope.
func generateTestTokensWithScope(userID, scope string) (string, error) {
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
		"scope": scope,
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims)
	accessToken.Header["kid"] = config.GetBootstrap().AuthJwkCertKeyID
	signedToken, err := accessToken.SignedString(key.GetPrivateKey())
	if err != nil {
		return "", err
	}

	_, err = db.GetDB().Exec(`
		INSERT INTO tokens (id, user_id, access_token, refresh_token, access_token_type,
			refresh_token_expires_at, access_token_expires_at, issued_at, scope, grant_type)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, tokenID, userID, signedToken, "refresh-token", "Bearer",
		refreshTokenExpiresAt, accessTokenExpiresAt, time.Now(), scope, "authorization_code")
	if err != nil {
		return "", err
	}

	_, err = db.GetDB().Exec(`
		INSERT INTO sessions (id, user_id, access_token, refresh_token, user_agent, ip_address, location, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, sessionID, userID, signedToken, "", "", "", "", time.Now(), accessTokenExpiresAt)

	return signedToken, err
}

func TestHandleUserInfo_ScopeClaims_OpenIDOnly(t *testing.T) {
	testutils.WithTestDB(t)

	userID := xid.New().String()
	_, _ = db.GetDB().Exec(`
		INSERT INTO users (id, username, email, password, given_name, family_name, phone_number)
		VALUES (?, 'user1', 'user1@example.com', 'pass', 'John', 'Doe', '+1234')
	`, userID)

	token, _ := generateTestTokensWithScope(userID, "openid")

	req := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	HandleUserInfo(rr, req)

	body := rr.Body.String()
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, body, `"sub"`)
	assert.NotContains(t, body, "name")
	assert.NotContains(t, body, "email")
	assert.NotContains(t, body, "phone")
}

func TestHandleUserInfo_ScopeClaims_ProfileOnly(t *testing.T) {
	testutils.WithTestDB(t)

	userID := xid.New().String()
	_, _ = db.GetDB().Exec(`
		INSERT INTO users (id, username, email, password, given_name, family_name)
		VALUES (?, 'user2', 'user2@example.com', 'pass', 'Jane', 'Smith')
	`, userID)

	token, _ := generateTestTokensWithScope(userID, "openid profile")

	req := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	HandleUserInfo(rr, req)

	body := rr.Body.String()
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, body, "Jane Smith")
	assert.Contains(t, body, "preferred_username")
	assert.NotContains(t, body, "email")
}

func TestHandleUserInfo_ScopeClaims_EmailOnly(t *testing.T) {
	testutils.WithTestDB(t)

	userID := xid.New().String()
	_, _ = db.GetDB().Exec(`
		INSERT INTO users (id, username, email, password, given_name, family_name)
		VALUES (?, 'user3', 'user3@example.com', 'pass', 'Bob', 'Jones')
	`, userID)

	token, _ := generateTestTokensWithScope(userID, "openid email")

	req := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	HandleUserInfo(rr, req)

	body := rr.Body.String()
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, body, "user3@example.com")
	assert.Contains(t, body, "email_verified")
	assert.NotContains(t, body, "preferred_username")
	assert.NotContains(t, body, "given_name")
}

func TestHandleUserInfo_ScopeClaims_NameFallsBackToUsername(t *testing.T) {
	testutils.WithTestDB(t)

	userID := xid.New().String()
	_, _ = db.GetDB().Exec(`
		INSERT INTO users (id, username, email, password)
		VALUES (?, 'johndoe', 'johndoe@example.com', 'pass')
	`, userID)

	token, _ := generateTestTokensWithScope(userID, "openid profile")

	req := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	HandleUserInfo(rr, req)

	body := rr.Body.String()
	assert.Equal(t, http.StatusOK, rr.Code)
	// name should fall back to username when given_name/family_name are empty
	assert.Contains(t, body, `"name":"johndoe"`)
}

func TestHandleUserInfo_ScopeClaims_PhoneAndAddress(t *testing.T) {
	testutils.WithTestDB(t)

	userID := xid.New().String()
	_, _ = db.GetDB().Exec(`
		INSERT INTO users (id, username, email, password, phone_number, address_street)
		VALUES (?, 'user4', 'user4@example.com', 'pass', '+9999', '123 Main St')
	`, userID)

	token, _ := generateTestTokensWithScope(userID, "openid phone address")

	req := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	HandleUserInfo(rr, req)

	body := rr.Body.String()
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, body, "+9999")
	assert.Contains(t, body, "123 Main St")
	assert.NotContains(t, body, "preferred_username")
}

func TestHandleUserInfo_PostBody(t *testing.T) {
	testutils.WithTestDB(t)

	userID := xid.New().String()
	_, _ = db.GetDB().Exec(`
		INSERT INTO users (id, username, email, password)
		VALUES (?, 'postuser', 'post@example.com', 'pass')
	`, userID)

	token, _ := generateTestTokensWithScope(userID, "openid profile email")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/userinfo", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.PostForm = map[string][]string{"access_token": {token}}
	rr := httptest.NewRecorder()
	HandleUserInfo(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "postuser")
}

func TestHandleUserInfo_FullProfile(t *testing.T) {
	testutils.WithTestDB(t)

	userID := xid.New().String()
	_, _ = db.GetDB().Exec(`
		INSERT INTO users (id, username, email, password, given_name, family_name, phone_number, picture, locale, zoneinfo, address_street, address_locality)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, userID, "testuser", "test@example.com", "hashedpassword", "John", "Doe", "+123456789", "http://pic.com", "en-US", "UTC", "Main St", "New York")

	accessToken, _ := generateTestTokens(userID)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rr := httptest.NewRecorder()

	HandleUserInfo(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	body := rr.Body.String()
	assert.Contains(t, body, "John Doe")
	// phone and address require their own scopes — not returned with openid profile email
	assert.NotContains(t, body, "+123456789")
	assert.NotContains(t, body, "Main St")
}

// Issue #5: all standard profile claims must be present (even as null) when profile scope is requested
func TestHandleUserInfo_ProfileScope_NullClaimsPresent(t *testing.T) {
	testutils.WithTestDB(t)

	userID := xid.New().String()
	// User with no profile fields set at all
	_, _ = db.GetDB().Exec(`INSERT INTO users (id, username, email, password) VALUES (?, 'barebones', '', 'pass')`, userID)

	token, _ := generateTestTokensWithScope(userID, "openid profile")

	req := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	HandleUserInfo(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))

	// All standard OIDC profile claims must be present (may be null, but the key must exist)
	for _, claim := range []string{"given_name", "family_name", "middle_name", "nickname", "website", "gender", "birthdate", "profile", "picture", "locale", "zoneinfo", "updated_at"} {
		_, exists := body[claim]
		assert.True(t, exists, "claim %q must be present in profile scope response", claim)
	}
}

// Issue #7: address claim must be present as null when address scope requested but user has no address data
func TestHandleUserInfo_AddressScope_NullWhenEmpty(t *testing.T) {
	testutils.WithTestDB(t)

	userID := xid.New().String()
	_, _ = db.GetDB().Exec(`INSERT INTO users (id, username, email, password) VALUES (?, 'noaddr', '', 'pass')`, userID)

	token, _ := generateTestTokensWithScope(userID, "openid address")

	req := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	HandleUserInfo(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))

	_, exists := body["address"]
	assert.True(t, exists, "address claim must be present even when user has no address data")
	assert.Nil(t, body["address"], "address must be null when user has no address data")
}

// Issue #7: phone_number must be present as null when phone scope requested but user has no phone
func TestHandleUserInfo_PhoneScope_NullWhenEmpty(t *testing.T) {
	testutils.WithTestDB(t)

	userID := xid.New().String()
	_, _ = db.GetDB().Exec(`INSERT INTO users (id, username, email, password) VALUES (?, 'nophone', '', 'pass')`, userID)

	token, _ := generateTestTokensWithScope(userID, "openid phone")

	req := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	HandleUserInfo(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))

	_, exists := body["phone_number"]
	assert.True(t, exists, "phone_number must be present even when user has no phone")
	assert.Nil(t, body["phone_number"], "phone_number must be null when user has no phone")
}

// Issue #8: phone_number_verified must always be emitted when phone scope is present
func TestHandleUserInfo_PhoneScope_IncludesVerified(t *testing.T) {
	testutils.WithTestDB(t)

	userID := xid.New().String()
	_, _ = db.GetDB().Exec(`INSERT INTO users (id, username, email, password, phone_number) VALUES (?, 'phoneverify', '', 'pass', '+1234')`, userID)

	token, _ := generateTestTokensWithScope(userID, "openid phone")

	req := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	HandleUserInfo(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))

	_, exists := body["phone_number_verified"]
	assert.True(t, exists, "phone_number_verified must always be present with phone scope")
}

func TestHandleUserInfo_CompleteProfile(t *testing.T) {
	testutils.WithTestDB(t)
	
	userID := xid.New().String()
	_, _ = db.GetDB().Exec(`
		INSERT INTO users (id, username, email, is_email_verified, password, given_name, family_name, phone_number, picture, locale, zoneinfo, address_street, address_locality, address_region, address_postal_code, address_country)
		VALUES (?, 'fulluser', 'full@test.com', 1, 'pass', 'John', 'Doe', '123456', 'http://pic', 'en-US', 'UTC', '123 St', 'City', 'Region', '12345', 'Country')
	`, userID)

	claims := &jwtutil.AccessTokenClaims{
		UserID:    userID,
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, _ := token.SignedString(key.GetPrivateKey())

	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	expiry := time.Now().Add(24 * time.Hour).UTC().Format("2006-01-02 15:04:05")

	_, _ = db.GetDB().Exec(`
		INSERT INTO sessions (id, user_id, access_token, refresh_token, user_agent, ip_address, location, created_at, expires_at)
		VALUES ('sess1', ?, ?, 'ref1', '', '', '', ?, ?)
	`, userID, signedToken, now, expiry)

	// Provide ALL columns for tokens table
	_, err := db.GetDB().Exec(`
		INSERT INTO tokens (id, user_id, access_token, refresh_token, access_token_type, refresh_token_expires_at, refresh_token_last_used_at, access_token_expires_at, issued_at, scope, grant_type, revoked_at)
		VALUES (1, ?, ?, 'ref1', 'Bearer', ?, NULL, ?, ?, 'openid profile email', 'password', NULL)
	`, userID, signedToken, expiry, expiry, now)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+signedToken)
	rr := httptest.NewRecorder()
	
	HandleUserInfo(rr, req)
	
	assert.Equal(t, http.StatusOK, rr.Code)
}

// TestUserInfo_WWWAuthenticate_MissingToken verifies RFC 6750 §3:
// "the resource server MUST include the HTTP WWW-Authenticate response header field"
// on 401 responses. No token → Bearer realm only (no error attributes).
func TestUserInfo_WWWAuthenticate_MissingToken(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	rr := httptest.NewRecorder()

	HandleUserInfo(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	wwwAuth := rr.Header().Get("WWW-Authenticate")
	assert.NotEmpty(t, wwwAuth, "RFC 6750 §3: WWW-Authenticate header MUST be present on 401")
	assert.Contains(t, wwwAuth, "Bearer", "WWW-Authenticate scheme must be Bearer")
}

// TestUserInfo_WWWAuthenticate_InvalidToken verifies RFC 6750 §3:
// invalid token → Bearer with error and error_description attributes.
func TestUserInfo_WWWAuthenticate_InvalidToken(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer not-a-valid-token")
	rr := httptest.NewRecorder()

	HandleUserInfo(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	wwwAuth := rr.Header().Get("WWW-Authenticate")
	assert.NotEmpty(t, wwwAuth, "RFC 6750 §3: WWW-Authenticate header MUST be present on 401")
	assert.Contains(t, wwwAuth, "Bearer")
	assert.Contains(t, wwwAuth, "error=")
}
