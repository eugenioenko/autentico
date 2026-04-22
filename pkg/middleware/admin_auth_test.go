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

// generateTestAccessToken creates a valid JWT access token for testing
func generateTestAccessToken(userID string) (string, error) {
	accessTokenExpiresAt := time.Now().Add(config.Get().AuthAccessTokenExpiration).UTC()

	accessClaims := jwt.MapClaims{
		"exp":   accessTokenExpiresAt.Unix(),
		"iat":   time.Now().Unix(),
		"iss":   config.GetBootstrap().AppAuthIssuer,
		"aud":   []string{config.GetBootstrap().AppAuthIssuer, "autentico-admin"},
		"sub":   userID,
		"typ":   "Bearer",
		"sid":   xid.New().String(),
		"scope": "openid profile email",
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims)
	accessToken.Header["kid"] = config.GetBootstrap().AuthJwkCertKeyID
	return accessToken.SignedString(key.GetPrivateKey())
}

func TestAdminAuthMiddlewareMissingAuth(t *testing.T) {
	_, err := db.InitTestDB()
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := AdminAuthMiddleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()

	wrapped.ServeHTTP(rr, req)

	// RFC 6750 §3.1: 401 MUST be returned; body text not specified for missing-credentials case
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.NotEmpty(t, rr.Header().Get("WWW-Authenticate"), "WWW-Authenticate must be present")
}

func TestAdminAuthMiddlewareInvalidFormat(t *testing.T) {
	_, err := db.InitTestDB()
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := AdminAuthMiddleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "InvalidFormat token")
	rr := httptest.NewRecorder()

	wrapped.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid Authorization header format")
}

func TestAdminAuthMiddlewareInvalidToken(t *testing.T) {
	_, err := db.InitTestDB()
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := AdminAuthMiddleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	rr := httptest.NewRecorder()

	wrapped.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid or expired token")
}

func TestAdminAuthMiddlewareNonAdminUser(t *testing.T) {
	_, err := db.InitTestDB()
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	// Create a regular (non-admin) user
	userID := xid.New().String()
	_, err = db.GetDB().Exec(`
		INSERT INTO users (id, username, email, password, role) VALUES (?, ?, ?, ?, ?)
	`, userID, "regularuser", "regular@example.com", "hashedpassword", "user")
	assert.NoError(t, err)

	// Generate a valid token for the non-admin user
	token, err := generateTestAccessToken(userID)
	assert.NoError(t, err)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := AdminAuthMiddleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	wrapped.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "Admin access required")
}

func TestAdminAuthMiddlewareWrongAudience(t *testing.T) {
	_, err := db.InitTestDB()
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	userID := xid.New().String()

	// Generate a token with wrong audience
	accessTokenExpiresAt := time.Now().Add(config.Get().AuthAccessTokenExpiration).UTC()
	accessClaims := jwt.MapClaims{
		"exp":   accessTokenExpiresAt.Unix(),
		"iat":   time.Now().Unix(),
		"iss":   config.GetBootstrap().AppAuthIssuer,
		"aud":   []string{"wrong-audience"},
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

	wrapped := AdminAuthMiddleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	wrapped.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "Token not issued for admin API")
}

// TestAdminAuthMiddleware_TokenFromOtherClient verifies that a valid token issued
// by a different client is rejected, even if the user has the admin role.
// This prevents the confused deputy attack where a malicious client obtains
// an admin user's token and replays it against the admin API.
func TestAdminAuthMiddleware_TokenFromOtherClient(t *testing.T) {
	testutils.WithTestDB(t)

	// Create an admin user
	userID := xid.New().String()
	_, err := db.GetDB().Exec(`
		INSERT INTO users (id, username, email, password, role) VALUES (?, ?, ?, ?, ?)
	`, userID, "adminuser", "admin@example.com", "hashedpassword", "admin")
	assert.NoError(t, err)

	// Generate a token as if issued by "attacker-client" — aud does NOT include "autentico-admin"
	accessTokenExpiresAt := time.Now().Add(config.Get().AuthAccessTokenExpiration).UTC()
	accessClaims := jwt.MapClaims{
		"exp":   accessTokenExpiresAt.Unix(),
		"iat":   time.Now().Unix(),
		"iss":   config.GetBootstrap().AppAuthIssuer,
		"aud":   []string{config.GetBootstrap().AppAuthIssuer, "attacker-client"},
		"sub":   userID,
		"typ":   "Bearer",
		"sid":   xid.New().String(),
		"scope": "openid profile email",
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims)
	accessToken.Header["kid"] = config.GetBootstrap().AuthJwkCertKeyID
	token, err := accessToken.SignedString(key.GetPrivateKey())
	assert.NoError(t, err)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := AdminAuthMiddleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	wrapped.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "Token not issued for admin API")
}

func TestAdminAuthMiddlewareUserNotFound(t *testing.T) {
	_, err := db.InitTestDB()
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	// Generate a valid token for a non-existent user
	userID := xid.New().String()
	token, err := generateTestAccessToken(userID)
	assert.NoError(t, err)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := AdminAuthMiddleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	wrapped.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "User not found")
}

func TestAdminAuthMiddlewareAdminUser(t *testing.T) {
	_, err := db.InitTestDB()
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	// Create an admin user
	userID := xid.New().String()
	_, err = db.GetDB().Exec(`
		INSERT INTO users (id, username, email, password, role) VALUES (?, ?, ?, ?, ?)
	`, userID, "adminuser", "admin@example.com", "hashedpassword", "admin")
	assert.NoError(t, err)

	// Generate a valid token for the admin user
	token, err := generateTestAccessToken(userID)
	assert.NoError(t, err)

	// Create a session and tokens row so the liveness checks pass
	sessionID := xid.New().String()
	_, err = db.GetDB().Exec(`
		INSERT INTO sessions (id, user_id, access_token, refresh_token, user_agent, ip_address, location, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, datetime('now', '+1 hour'))
	`, sessionID, userID, token, "", "", "", "")
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

	wrapped := AdminAuthMiddleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	wrapped.ServeHTTP(rr, req)

	// Debug: print response if not successful
	if rr.Code != http.StatusOK {
		t.Logf("Response body: %s", rr.Body.String())
	}

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.True(t, handlerCalled, "Handler should be called for admin user")
}

func TestAdminAuthMiddleware_SessionDeactivated(t *testing.T) {
	testutils.WithTestDB(t)

	// Create an admin user
	userID := xid.New().String()
	_, _ = db.GetDB().Exec(`
		INSERT INTO users (id, username, email, password, role) VALUES (?, ?, ?, ?, ?)
	`, userID, "adminuser", "admin@example.com", "hashed", "admin")

	// Generate a valid token
	token, _ := generateTestAccessToken(userID)

	// Create a deactivated session
	sessionID := xid.New().String()
	_, _ = db.GetDB().Exec(`
		INSERT INTO sessions (id, user_id, access_token, refresh_token, user_agent, ip_address, location, created_at, expires_at, deactivated_at)
		VALUES (?, ?, ?, ?, '', '', '', CURRENT_TIMESTAMP, datetime('now', '+1 hour'), CURRENT_TIMESTAMP)
	`, sessionID, userID, token, "")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := AdminAuthMiddleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	wrapped.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "Session has been deactivated")
}

// TestAdminAuthMiddleware_TokenRevoked verifies that a token marked
// revoked in the tokens table (via /oauth2/revoke, RFC 7009) is rejected
// by the admin middleware even when the session is still active.
func TestAdminAuthMiddleware_TokenRevoked(t *testing.T) {
	testutils.WithTestDB(t)

	userID := xid.New().String()
	_, err := db.GetDB().Exec(
		`INSERT INTO users (id, username, email, password, role) VALUES (?, ?, ?, ?, 'admin')`,
		userID, "revokedadminuser", "revoked-admin@example.com", "hashed")
	assert.NoError(t, err)

	token, err := generateTestAccessToken(userID)
	assert.NoError(t, err)

	// Active session — the session gate should pass.
	sessionID := xid.New().String()
	_, err = db.GetDB().Exec(`
		INSERT INTO sessions (id, user_id, access_token, refresh_token, user_agent, ip_address, location, created_at, expires_at)
		VALUES (?, ?, ?, ?, '', '', '', CURRENT_TIMESTAMP, datetime('now', '+1 hour'))
	`, sessionID, userID, token, "")
	assert.NoError(t, err)

	// Persisted, revoked tokens row — the new check should catch this.
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

	wrapped := AdminAuthMiddleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	wrapped.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "Token has been revoked")
}

// TestAdminAuthMiddleware_WWWAuthenticate_On401 verifies RFC 6750 §3.1:
// all 401 responses from the admin auth middleware MUST include WWW-Authenticate.
func TestAdminAuthMiddleware_WWWAuthenticate_On401(t *testing.T) {
	testutils.WithTestDB(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrapped := AdminAuthMiddleware(handler)

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

// TestAdminAuthMiddleware_CaseInsensitiveBearer verifies that lowercase "bearer" is accepted.
func TestAdminAuthMiddleware_CaseInsensitiveBearer(t *testing.T) {
	testutils.WithTestDB(t)

	userID := xid.New().String()
	_, _ = db.GetDB().Exec(`INSERT INTO users (id, username, email, password, role) VALUES (?, 'admin2', 'admin2@example.com', 'hashed', 'admin')`, userID)

	token, _ := generateTestAccessToken(userID)

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
	wrapped := AdminAuthMiddleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "bearer "+token) // lowercase
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code, "lowercase 'bearer' must be accepted by admin middleware")
	assert.True(t, handlerCalled)
}

// generateClientCredentialsTestToken mints a JWT shaped like one issued via the
// client_credentials grant (RFC 6749 §4.4): sub == azp == client_id, no user.
func generateClientCredentialsTestToken(clientID string) (string, error) {
	accessTokenExpiresAt := time.Now().Add(config.Get().AuthAccessTokenExpiration).UTC()
	accessClaims := jwt.MapClaims{
		"exp":   accessTokenExpiresAt.Unix(),
		"iat":   time.Now().Unix(),
		"iss":   config.GetBootstrap().AppAuthIssuer,
		"aud":   []string{config.GetBootstrap().AppAuthIssuer, clientID, "autentico-admin"},
		"sub":   clientID,
		"azp":   clientID,
		"typ":   "Bearer",
		"sid":   xid.New().String(),
		"scope": "read",
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims)
	accessToken.Header["kid"] = config.GetBootstrap().AuthJwkCertKeyID
	return accessToken.SignedString(key.GetPrivateKey())
}

// insertTestClient seeds a client row directly into the test DB.
func insertTestClient(t *testing.T, clientID, clientType string, isAdminServiceAccount bool) {
	t.Helper()
	_, err := db.GetDB().Exec(`
		INSERT INTO clients (
			id, client_id, client_secret, client_name, client_type, redirect_uris,
			post_logout_redirect_uris, grant_types, response_types, scopes,
			token_endpoint_auth_method, is_active, is_admin_service_account
		) VALUES (?, ?, '', ?, ?, '[]', '[]', '["client_credentials"]', '["code"]', 'read', 'client_secret_basic', 1, ?)
	`, xid.New().String(), clientID, "Test "+clientID, clientType, isAdminServiceAccount)
	assert.NoError(t, err)
}

// Positive: confidential client with IsAdminServiceAccount=true + client_credentials token → 200
func TestAdminAuthMiddleware_ServiceAccount_Accepted(t *testing.T) {
	testutils.WithTestDB(t)

	clientID := "svc-admin-" + xid.New().String()
	insertTestClient(t, clientID, "confidential", true)

	token, err := generateClientCredentialsTestToken(clientID)
	assert.NoError(t, err)

	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})
	wrapped := AdminAuthMiddleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code, "expected 200 for service-account client")
	assert.True(t, handlerCalled, "handler should be called for service-account client")
}

// Negative: confidential client WITHOUT the flag → token is treated as user-path
// and fails because the "user" (a client_id) doesn't exist in users table.
func TestAdminAuthMiddleware_ServiceAccount_FlagMissing(t *testing.T) {
	testutils.WithTestDB(t)

	clientID := "svc-noflag-" + xid.New().String()
	insertTestClient(t, clientID, "confidential", false)

	token, err := generateClientCredentialsTestToken(clientID)
	assert.NoError(t, err)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrapped := AdminAuthMiddleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	// Falls through to user-path: no user with ID=clientID exists → 401 User not found
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "User not found")
}

// Negative: client is inactive even though flag is set → rejected (falls through to user-path).
func TestAdminAuthMiddleware_ServiceAccount_InactiveClient(t *testing.T) {
	testutils.WithTestDB(t)

	clientID := "svc-inactive-" + xid.New().String()
	// Insert as active, then deactivate.
	insertTestClient(t, clientID, "confidential", true)
	_, err := db.GetDB().Exec(`UPDATE clients SET is_active = 0 WHERE client_id = ?`, clientID)
	assert.NoError(t, err)

	token, err := generateClientCredentialsTestToken(clientID)
	assert.NoError(t, err)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrapped := AdminAuthMiddleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	assert.NotEqual(t, http.StatusOK, rr.Code, "inactive service-account client must not be accepted")
}

// Negative: service-account token that lacks autentico-admin in aud → 403 at aud check.
func TestAdminAuthMiddleware_ServiceAccount_WrongAudience(t *testing.T) {
	testutils.WithTestDB(t)

	clientID := "svc-wrongaud-" + xid.New().String()
	insertTestClient(t, clientID, "confidential", true)

	// Mint a token without "autentico-admin" in aud.
	accessTokenExpiresAt := time.Now().Add(config.Get().AuthAccessTokenExpiration).UTC()
	accessClaims := jwt.MapClaims{
		"exp":   accessTokenExpiresAt.Unix(),
		"iat":   time.Now().Unix(),
		"iss":   config.GetBootstrap().AppAuthIssuer,
		"aud":   []string{config.GetBootstrap().AppAuthIssuer, clientID},
		"sub":   clientID,
		"azp":   clientID,
		"typ":   "Bearer",
		"sid":   xid.New().String(),
		"scope": "read",
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims)
	accessToken.Header["kid"] = config.GetBootstrap().AuthJwkCertKeyID
	token, err := accessToken.SignedString(key.GetPrivateKey())
	assert.NoError(t, err)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrapped := AdminAuthMiddleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "Token not issued for admin API")
}

func TestAdminAuthMiddleware_DbError(t *testing.T) {
	testutils.WithTestDB(t)
	userID := xid.New().String()
	token, _ := generateTestAccessToken(userID)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := AdminAuthMiddleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	// Close DB to trigger error in UserByID
	db.CloseDB()

	wrapped.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "User not found")
}
