package session

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/key"
	"github.com/rs/xid"
	testutils "github.com/eugenioenko/autentico/tests/utils"

	"github.com/stretchr/testify/assert"
)

// generateTestAccessToken creates a valid JWT access token for testing
func generateTestAccessToken(userID string) (string, string, error) {
	sessionID := xid.New().String()
	accessTokenExpiresAt := time.Now().Add(config.Get().AuthAccessTokenExpiration).UTC()

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
	return signedToken, sessionID, err
}

func TestHandleLogout(t *testing.T) {
	testutils.WithTestDB(t)

	// Create a test user directly in the database
	userID := xid.New().String()
	_, err := db.GetDB().Exec(`
		INSERT INTO users (id, username, email, password) VALUES (?, ?, ?, ?)
	`, userID, "logoutuser", "logout@example.com", "hashedpassword")
	assert.NoError(t, err)

	// Generate a real JWT token
	accessToken, sessionID, err := generateTestAccessToken(userID)
	assert.NoError(t, err)

	// Insert a session with the real access token
	_, err = db.GetDB().Exec(`
		INSERT INTO sessions (id, user_id, access_token, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?)
	`, sessionID, userID, accessToken, time.Now(), time.Now().Add(1*time.Hour))
	assert.NoError(t, err)

	// Perform logout with the real JWT token
	req := httptest.NewRequest(http.MethodPost, "/oauth2/logout", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rr := httptest.NewRecorder()

	HandleLogout(rr, req)

	// Verify the response
	assert.Equal(t, http.StatusOK, rr.Code)

	// Verify the session is deactivated
	var deactivatedAt sql.NullTime
	err = db.GetDB().QueryRow(`SELECT deactivated_at FROM sessions WHERE id = ?`, sessionID).Scan(&deactivatedAt)
	assert.NoError(t, err)
	assert.True(t, deactivatedAt.Valid, "deactivated_at should be set")
}

func TestHandleLogoutMissingAuth(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/logout", nil)
	rr := httptest.NewRecorder()

	HandleLogout(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "Authorization header is required")
}

func TestHandleLogoutInvalidToken(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/logout", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	rr := httptest.NewRecorder()

	HandleLogout(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid or expired token")
}

func TestHandleLogoutInvalidAuthFormat(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/logout", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rr := httptest.NewRecorder()

	HandleLogout(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid Authorization header")
}
