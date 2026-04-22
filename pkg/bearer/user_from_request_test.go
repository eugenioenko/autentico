package bearer_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/eugenioenko/autentico/pkg/bearer"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/key"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/rs/xid"

	"github.com/stretchr/testify/assert"
)

// setupAuthenticatedUser creates a user, JWT token, and session in DB,
// returning the bearer token string.
func setupAuthenticatedUser(t *testing.T) (string, string) {
	t.Helper()

	userID := xid.New().String()
	sessionID := xid.New().String()
	accessTokenExpiresAt := time.Now().Add(config.Get().AuthAccessTokenExpiration).UTC()

	_, err := db.GetDB().Exec(`
		INSERT INTO users (id, username, email, password, role) VALUES (?, ?, ?, ?, ?)
	`, userID, "authuser-"+userID[:8], "auth-"+userID[:8]+"@example.com", "hashedpassword", "admin")
	assert.NoError(t, err)

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
	assert.NoError(t, err)

	_, err = db.GetDB().Exec(`
		INSERT INTO sessions (id, user_id, access_token, refresh_token, user_agent, ip_address, location, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, sessionID, userID, signedToken, "refresh-token-placeholder", "", "", "", time.Now(), time.Now().Add(1*time.Hour))
	assert.NoError(t, err)

	_, err = db.GetDB().Exec(`
		INSERT INTO tokens (id, user_id, access_token, refresh_token, access_token_type,
			refresh_token_expires_at, access_token_expires_at, issued_at, scope, grant_type)
		VALUES (?, ?, ?, ?, 'Bearer', ?, ?, ?, 'openid profile email', 'password')
	`, "tok-"+sessionID[:6], userID, signedToken, "refresh-"+sessionID[:6], accessTokenExpiresAt, accessTokenExpiresAt, time.Now())
	assert.NoError(t, err)

	return signedToken, userID
}

func TestUserFromRequest_MissingAuth(t *testing.T) {
	testutils.WithTestDB(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := bearer.UserFromRequest(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing Authorization header")
}

func TestUserFromRequest_InvalidAuthFormat(t *testing.T) {
	testutils.WithTestDB(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	_, err := bearer.UserFromRequest(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid Authorization header")
}

func TestUserFromRequest_InvalidToken(t *testing.T) {
	testutils.WithTestDB(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	_, err := bearer.UserFromRequest(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid token")
}

func TestUserFromRequest_NoSession(t *testing.T) {
	testutils.WithTestDB(t)

	userID := xid.New().String()
	sessionID := xid.New().String()
	accessTokenExpiresAt := time.Now().Add(config.Get().AuthAccessTokenExpiration).UTC()
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
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+signedToken)
	_, err = bearer.UserFromRequest(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid session")
}

func TestUserFromRequest_Valid(t *testing.T) {
	testutils.WithTestDB(t)
	token, _ := setupAuthenticatedUser(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	usr, err := bearer.UserFromRequest(req)
	assert.NoError(t, err)
	assert.NotNil(t, usr)
}

// Regression for https://github.com/eugenioenko/autentico/issues/225:
// a token whose session has been deactivated must not be accepted.
// SessionByAccessToken filters deactivated rows at the read layer, so the
// error surfaces as "session not found" rather than a per-field rejection.
func TestUserFromRequest_DeactivatedSession(t *testing.T) {
	testutils.WithTestDB(t)
	token, _ := setupAuthenticatedUser(t)
	_, err := db.GetDB().Exec(
		`UPDATE sessions SET deactivated_at = CURRENT_TIMESTAMP WHERE access_token = ?`,
		token,
	)
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	_, err = bearer.UserFromRequest(req)
	assert.Error(t, err)
}

// A token revoked via /oauth2/revoke (RFC 7009 — sets tokens.revoked_at)
// must also be rejected. Same class as #225 but on the tokens table.
// TokenByAccessToken filters revoked rows at the read layer; the caller
// treats ErrNoRows as a rejection.
func TestUserFromRequest_RevokedToken(t *testing.T) {
	testutils.WithTestDB(t)
	token, _ := setupAuthenticatedUser(t)
	_, err := db.GetDB().Exec(
		`UPDATE tokens SET revoked_at = CURRENT_TIMESTAMP WHERE access_token = ?`,
		token,
	)
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	_, err = bearer.UserFromRequest(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "revoked")
}
