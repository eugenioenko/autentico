package middleware

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

func generateAccountTestAccessToken(userID string) (string, error) {
	accessTokenExpiresAt := time.Now().Add(config.Get().AuthAccessTokenExpiration).UTC()

	accessClaims := jwt.MapClaims{
		"exp":   accessTokenExpiresAt.Unix(),
		"iat":   time.Now().Unix(),
		"iss":   config.GetBootstrap().AppAuthIssuer,
		"aud":   []string{config.GetBootstrap().AppAuthIssuer, config.AccountClientID},
		"sub":   userID,
		"typ":   "Bearer",
		"sid":   xid.New().String(),
		"scope": "openid profile email",
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims)
	accessToken.Header["kid"] = config.GetBootstrap().AuthJwkCertKeyID
	return accessToken.SignedString(key.GetPrivateKey())
}

func TestAccountAuthMiddleware_MissingAuth(t *testing.T) {
	testutils.WithTestDB(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := AccountAuthMiddleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()

	wrapped.ServeHTTP(rr, req)

	// RFC 6750 §3.1: 401 MUST be returned
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.NotEmpty(t, rr.Header().Get("WWW-Authenticate"), "WWW-Authenticate must be present")
}

func TestAccountAuthMiddleware_InvalidFormat(t *testing.T) {
	testutils.WithTestDB(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := AccountAuthMiddleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "InvalidFormat token")
	rr := httptest.NewRecorder()

	wrapped.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid Authorization header format")
}

func TestAccountAuthMiddleware_InvalidToken(t *testing.T) {
	testutils.WithTestDB(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := AccountAuthMiddleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	rr := httptest.NewRecorder()

	wrapped.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid or expired token")
}

func TestAccountAuthMiddleware_WrongAudience(t *testing.T) {
	testutils.WithTestDB(t)

	userID := xid.New().String()

	accessTokenExpiresAt := time.Now().Add(config.Get().AuthAccessTokenExpiration).UTC()
	accessClaims := jwt.MapClaims{
		"exp":   accessTokenExpiresAt.Unix(),
		"iat":   time.Now().Unix(),
		"iss":   config.GetBootstrap().AppAuthIssuer,
		"aud":   []string{config.GetBootstrap().AppAuthIssuer, "third-party-app"},
		"sub":   userID,
		"typ":   "Bearer",
		"sid":   xid.New().String(),
		"scope": "openid",
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims)
	accessToken.Header["kid"] = config.GetBootstrap().AuthJwkCertKeyID
	token, err := accessToken.SignedString(key.GetPrivateKey())
	assert.NoError(t, err)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := AccountAuthMiddleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	wrapped.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "Token not issued for account API")
}

// TestAccountAuthMiddleware_RegularUserAccepted verifies that non-admin users
// are accepted (unlike AdminAuthMiddleware which requires admin role).
func TestAccountAuthMiddleware_RegularUserAccepted(t *testing.T) {
	testutils.WithTestDB(t)

	userID := xid.New().String()
	_, err := db.GetDB().Exec(`
		INSERT INTO users (id, username, email, password, role) VALUES (?, ?, ?, ?, ?)
	`, userID, "regularuser", "regular@example.com", "hashedpassword", "user")
	assert.NoError(t, err)

	token, err := generateAccountTestAccessToken(userID)
	assert.NoError(t, err)

	sessionID := xid.New().String()
	_, err = db.GetDB().Exec(`
		INSERT INTO sessions (id, user_id, access_token, refresh_token, user_agent, ip_address, location, created_at, expires_at)
		VALUES (?, ?, ?, ?, '', '', '', CURRENT_TIMESTAMP, datetime('now', '+1 hour'))
	`, sessionID, userID, token, "")
	assert.NoError(t, err)

	now := time.Now().UTC()
	_, err = db.GetDB().Exec(`
		INSERT INTO tokens (id, user_id, access_token, refresh_token, access_token_type,
			refresh_token_expires_at, access_token_expires_at, issued_at, scope, grant_type)
		VALUES (?, ?, ?, ?, 'Bearer', ?, ?, ?, 'openid', 'password')
	`, "tok-"+sessionID[:6], userID, token, "refresh-"+sessionID[:6], now.Add(time.Hour), now.Add(time.Hour), now)
	assert.NoError(t, err)

	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	wrapped := AccountAuthMiddleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	wrapped.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.True(t, handlerCalled, "Handler should be called for regular user with autentico-account audience")
}

// TestAccountAuthMiddleware_AdminAudienceAccepted verifies that tokens with
// autentico-admin audience are also accepted by the account middleware.
func TestAccountAuthMiddleware_AdminAudienceAccepted(t *testing.T) {
	testutils.WithTestDB(t)

	userID := xid.New().String()
	_, err := db.GetDB().Exec(`
		INSERT INTO users (id, username, email, password, role) VALUES (?, ?, ?, ?, ?)
	`, userID, "adminuser", "admin@example.com", "hashedpassword", "admin")
	assert.NoError(t, err)

	token, err := generateTestAccessToken(userID) // uses autentico-admin audience
	assert.NoError(t, err)

	sessionID := xid.New().String()
	_, err = db.GetDB().Exec(`
		INSERT INTO sessions (id, user_id, access_token, refresh_token, user_agent, ip_address, location, created_at, expires_at)
		VALUES (?, ?, ?, ?, '', '', '', CURRENT_TIMESTAMP, datetime('now', '+1 hour'))
	`, sessionID, userID, token, "")
	assert.NoError(t, err)

	now := time.Now().UTC()
	_, err = db.GetDB().Exec(`
		INSERT INTO tokens (id, user_id, access_token, refresh_token, access_token_type,
			refresh_token_expires_at, access_token_expires_at, issued_at, scope, grant_type)
		VALUES (?, ?, ?, ?, 'Bearer', ?, ?, ?, 'openid', 'password')
	`, "tok-"+sessionID[:6], userID, token, "refresh-"+sessionID[:6], now.Add(time.Hour), now.Add(time.Hour), now)
	assert.NoError(t, err)

	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	wrapped := AccountAuthMiddleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	wrapped.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.True(t, handlerCalled, "Handler should be called for admin user with autentico-admin audience")
}

func TestAccountAuthMiddleware_UserNotFound(t *testing.T) {
	testutils.WithTestDB(t)

	userID := xid.New().String()
	token, err := generateAccountTestAccessToken(userID)
	assert.NoError(t, err)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := AccountAuthMiddleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	wrapped.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "User not found")
}

func TestAccountAuthMiddleware_SessionDeactivated(t *testing.T) {
	testutils.WithTestDB(t)

	userID := xid.New().String()
	_, _ = db.GetDB().Exec(`
		INSERT INTO users (id, username, email, password, role) VALUES (?, ?, ?, ?, ?)
	`, userID, "testuser", "test@example.com", "hashed", "user")

	token, _ := generateAccountTestAccessToken(userID)

	sessionID := xid.New().String()
	_, _ = db.GetDB().Exec(`
		INSERT INTO sessions (id, user_id, access_token, refresh_token, user_agent, ip_address, location, created_at, expires_at, deactivated_at)
		VALUES (?, ?, ?, ?, '', '', '', CURRENT_TIMESTAMP, datetime('now', '+1 hour'), CURRENT_TIMESTAMP)
	`, sessionID, userID, token, "")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := AccountAuthMiddleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	wrapped.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "Session has been deactivated")
}

func TestAccountAuthMiddleware_TokenRevoked(t *testing.T) {
	testutils.WithTestDB(t)

	userID := xid.New().String()
	_, err := db.GetDB().Exec(
		`INSERT INTO users (id, username, email, password, role) VALUES (?, ?, ?, ?, 'user')`,
		userID, "revokeduser", "revoked@example.com", "hashed")
	assert.NoError(t, err)

	token, err := generateAccountTestAccessToken(userID)
	assert.NoError(t, err)

	sessionID := xid.New().String()
	_, err = db.GetDB().Exec(`
		INSERT INTO sessions (id, user_id, access_token, refresh_token, user_agent, ip_address, location, created_at, expires_at)
		VALUES (?, ?, ?, ?, '', '', '', CURRENT_TIMESTAMP, datetime('now', '+1 hour'))
	`, sessionID, userID, token, "")
	assert.NoError(t, err)

	now := time.Now().UTC()
	_, err = db.GetDB().Exec(`
		INSERT INTO tokens (id, user_id, access_token, refresh_token, access_token_type,
			refresh_token_expires_at, access_token_expires_at, issued_at, scope, grant_type, revoked_at)
		VALUES (?, ?, ?, 'refresh', 'Bearer', ?, ?, ?, 'openid', 'password', ?)
	`, "tok-"+userID[:6], userID, token, now.Add(time.Hour), now.Add(time.Hour), now, now)
	assert.NoError(t, err)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := AccountAuthMiddleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	wrapped.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "Token has been revoked")
}

// RFC 6750 §3.1: all 401 responses MUST include WWW-Authenticate.
func TestAccountAuthMiddleware_WWWAuthenticate_On401(t *testing.T) {
	testutils.WithTestDB(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrapped := AccountAuthMiddleware(handler)

	cases := []struct {
		name   string
		header string
	}{
		{"missing token", ""},
		{"invalid format", "Basic dXNlcjpwYXNz"},
		{"invalid token", "Bearer not-a-valid-token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			rr := httptest.NewRecorder()
			wrapped.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusUnauthorized, rr.Code)
			wwwAuth := rr.Header().Get("WWW-Authenticate")
			assert.NotEmpty(t, wwwAuth, "RFC 6750 §3.1: WWW-Authenticate MUST be present on 401")
			assert.Contains(t, wwwAuth, "Bearer")
		})
	}
}

func TestAccountAuthMiddleware_InsufficientScope(t *testing.T) {
	testutils.WithTestDB(t)

	userID := xid.New().String()
	_, _ = db.GetDB().Exec(`INSERT INTO users (id, username, email, password, role) VALUES (?, 'scopeuser', 'scope@example.com', 'hashed', 'user')`, userID)

	accessClaims := jwt.MapClaims{
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"iss":   config.GetBootstrap().AppAuthIssuer,
		"aud":   []string{config.GetBootstrap().AppAuthIssuer, config.AccountClientID},
		"sub":   userID,
		"typ":   "Bearer",
		"sid":   xid.New().String(),
		"scope": "openid",
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims)
	accessToken.Header["kid"] = config.GetBootstrap().AuthJwkCertKeyID
	token, err := accessToken.SignedString(key.GetPrivateKey())
	assert.NoError(t, err)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrapped := AccountAuthMiddleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "insufficient_scope")
}

func TestHasRequiredScopes(t *testing.T) {
	assert.True(t, hasRequiredScopes("openid profile email", []string{"openid", "profile", "email"}))
	assert.True(t, hasRequiredScopes("openid profile email offline_access", []string{"openid", "profile", "email"}))
	assert.False(t, hasRequiredScopes("openid", []string{"openid", "profile", "email"}))
	assert.False(t, hasRequiredScopes("openid profile", []string{"openid", "profile", "email"}))
	assert.False(t, hasRequiredScopes("", []string{"openid", "profile", "email"}))
	assert.True(t, hasRequiredScopes("openid profile email", []string{}))
}

// Verify that lowercase "bearer" is accepted (RFC 6750 §2.1 / RFC 7235).
func TestAccountAuthMiddleware_CaseInsensitiveBearer(t *testing.T) {
	testutils.WithTestDB(t)

	userID := xid.New().String()
	_, _ = db.GetDB().Exec(`INSERT INTO users (id, username, email, password, role) VALUES (?, 'caseuser', 'case@example.com', 'hashed', 'user')`, userID)

	token, _ := generateAccountTestAccessToken(userID)

	sessionID := xid.New().String()
	_, _ = db.GetDB().Exec(`
		INSERT INTO sessions (id, user_id, access_token, refresh_token, user_agent, ip_address, location, created_at, expires_at)
		VALUES (?, ?, ?, ?, '', '', '', CURRENT_TIMESTAMP, datetime('now', '+1 hour'))
	`, sessionID, userID, token, "")
	now := time.Now().UTC()
	_, _ = db.GetDB().Exec(`
		INSERT INTO tokens (id, user_id, access_token, refresh_token, access_token_type,
			refresh_token_expires_at, access_token_expires_at, issued_at, scope, grant_type)
		VALUES (?, ?, ?, ?, 'Bearer', ?, ?, ?, 'openid', 'password')
	`, "tok-"+sessionID[:6], userID, token, "refresh-"+sessionID[:6], now.Add(time.Hour), now.Add(time.Hour), now)

	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})
	wrapped := AccountAuthMiddleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "bearer "+token) // lowercase
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code, "lowercase 'bearer' must be accepted")
	assert.True(t, handlerCalled)
}
