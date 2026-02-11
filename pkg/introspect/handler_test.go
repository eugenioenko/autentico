package introspect

import (
	"bytes"
	"encoding/json"
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

// generateTestTokenAndStore creates a valid JWT access token and stores it in the database for testing
func generateTestTokenAndStore(userID string) (string, string, error) {
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

func TestHandleIntrospectEmptyBody(t *testing.T) {
	_, err := db.InitTestDB()
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", nil)
	rr := httptest.NewRecorder()

	HandleIntrospect(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid JSON payload")
}

func TestHandleIntrospectInvalidJSON(t *testing.T) {
	_, err := db.InitTestDB()
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", bytes.NewReader([]byte("invalid json")))
	rr := httptest.NewRecorder()

	HandleIntrospect(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid JSON payload")
}

func TestHandleIntrospectMissingToken(t *testing.T) {
	_, err := db.InitTestDB()
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	reqBody := IntrospectRequest{Token: ""}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	HandleIntrospect(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Token is required")
}

func TestHandleIntrospectInvalidToken(t *testing.T) {
	_, err := db.InitTestDB()
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	reqBody := IntrospectRequest{Token: "invalid-token"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	HandleIntrospect(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestHandleIntrospectValidToken(t *testing.T) {
	_, err := db.InitTestDB()
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	// Create a test user
	userID := xid.New().String()
	_, err = db.GetDB().Exec(`
		INSERT INTO users (id, username, email, password) VALUES (?, ?, ?, ?)
	`, userID, "introspectuser", "introspect@example.com", "hashedpassword")
	assert.NoError(t, err)

	// Generate and store a token
	accessToken, _, err := generateTestTokenAndStore(userID)
	assert.NoError(t, err)

	reqBody := IntrospectRequest{Token: accessToken}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", bytes.NewReader(body))
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
	assert.Equal(t, userID, token.UserID)
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
	_, err := db.InitTestDB()
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", nil)
	req.Body = nil // explicitly nil body
	rr := httptest.NewRecorder()

	HandleIntrospect(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleIntrospectTokenNotInDB(t *testing.T) {
	_, err := db.InitTestDB()
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	// Create a valid JWT but don't store it in tokens table
	accessTokenExpiresAt := time.Now().Add(config.Get().AuthAccessTokenExpiration).UTC()
	claims := jwt.MapClaims{
		"exp":   accessTokenExpiresAt.Unix(),
		"iat":   time.Now().Unix(),
		"iss":   config.Get().AppAuthIssuer,
		"aud":   config.Get().AuthAccessTokenAudience,
		"sub":   "some-user-id",
		"typ":   "Bearer",
		"sid":   xid.New().String(),
		"scope": "openid",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = config.Get().AuthJwkCertKeyID
	signedToken, err := token.SignedString(key.GetPrivateKey())
	assert.NoError(t, err)

	reqBody := IntrospectRequest{Token: signedToken}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	HandleIntrospect(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestHandleIntrospectTokenNoSession(t *testing.T) {
	_, err := db.InitTestDB()
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	userID := xid.New().String()
	_, err = db.GetDB().Exec(`
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
		"iss":   config.Get().AppAuthIssuer,
		"aud":   config.Get().AuthAccessTokenAudience,
		"sub":   userID,
		"typ":   "Bearer",
		"sid":   xid.New().String(),
		"scope": "openid",
	}
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	jwtToken.Header["kid"] = config.Get().AuthJwkCertKeyID
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
	rr := httptest.NewRecorder()

	HandleIntrospect(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "Failed to retrieve session")
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
