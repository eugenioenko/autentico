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
	"github.com/rs/xid"
	"github.com/stretchr/testify/assert"
)

// generateTestAccessToken creates a valid JWT access token for testing
func generateTestAccessToken(userID string) (string, error) {
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
	return accessToken.SignedString(key.GetPrivateKey())
}

func TestAdminAuthMiddlewareMissingAuth(t *testing.T) {
	_, err := db.InitTestDB("../../db/test.db")
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

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "Missing Authorization header")
}

func TestAdminAuthMiddlewareInvalidFormat(t *testing.T) {
	_, err := db.InitTestDB("../../db/test.db")
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
	_, err := db.InitTestDB("../../db/test.db")
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
	_, err := db.InitTestDB("../../db/test.db")
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

func TestAdminAuthMiddlewareAdminUser(t *testing.T) {
	_, err := db.InitTestDB("../../db/test.db")
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
