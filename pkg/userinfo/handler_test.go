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
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/rs/xid"

	"github.com/stretchr/testify/assert"
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
		"iss":   config.Get().AppAuthIssuer,
		"aud":   config.Get().AuthAccessTokenAudience,
		"sub":   userID,
		"typ":   "Bearer",
		"sid":   sessionID,
		"scope": "openid profile email",
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims)
	accessToken.Header["kid"] = config.Get().AuthJwkCertKeyID
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
	assert.Contains(t, rr.Body.String(), "Authorization header is required")
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
	assert.Contains(t, rr.Body.String(), "Invalid Authorization header")
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
		"iss":   config.Get().AppAuthIssuer,
		"aud":   config.Get().AuthAccessTokenAudience,
		"sub":   userID,
		"typ":   "Bearer",
		"sid":   xid.New().String(),
		"scope": "openid profile email",
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims)
	accessToken.Header["kid"] = config.Get().AuthJwkCertKeyID
	signedToken, err := accessToken.SignedString(key.GetPrivateKey())
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+signedToken)
	rr := httptest.NewRecorder()

	HandleUserInfo(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid or expired token")
}
