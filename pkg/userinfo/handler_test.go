package userinfo

import (
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
	assert.Contains(t, rr.Body.String(), "Access token is required")
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
	assert.Contains(t, rr.Body.String(), "Access token is required")
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
	assert.Contains(t, body, "+123456789")
	assert.Contains(t, body, "Main St")
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
