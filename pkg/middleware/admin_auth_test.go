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
		"aud":   config.Get().AuthAccessTokenAudience,
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

	// ValidateAccessToken already checks audience, so this returns 401
	assert.True(t, rr.Code == http.StatusUnauthorized || rr.Code == http.StatusForbidden)
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

	// Create a session for this token so the session check passes
	sessionID := xid.New().String()
	_, err = db.GetDB().Exec(`
		INSERT INTO sessions (id, user_id, access_token, refresh_token, user_agent, ip_address, location, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, datetime('now', '+1 hour'))
	`, sessionID, userID, token, "", "", "", "")
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
