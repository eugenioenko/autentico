package user

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
	"github.com/eugenioenko/autentico/pkg/model"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/rs/xid"
	"strings"

	"github.com/stretchr/testify/assert"
)

// setupAuthenticatedUser creates a user, JWT token, and session in DB, returning the bearer token string
func setupAuthenticatedUser(t *testing.T) (string, string) {
	t.Helper()

	userID := xid.New().String()
	sessionID := xid.New().String()
	accessTokenExpiresAt := time.Now().Add(config.Get().AuthAccessTokenExpiration).UTC()

	// Create user directly in DB
	_, err := db.GetDB().Exec(`
		INSERT INTO users (id, username, email, password, role) VALUES (?, ?, ?, ?, ?)
	`, userID, "authuser-"+userID[:8], "auth-"+userID[:8]+"@example.com", "hashedpassword", "admin")
	assert.NoError(t, err)

	// Generate JWT access token
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

	// Create session in DB with the access token
	_, err = db.GetDB().Exec(`
		INSERT INTO sessions (id, user_id, access_token, refresh_token, user_agent, ip_address, location, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, sessionID, userID, signedToken, "refresh-token-placeholder", "", "", "", time.Now(), time.Now().Add(1*time.Hour))
	assert.NoError(t, err)

	return signedToken, userID
}

// --- GetUserFromRequest tests ---

func TestGetUserFromRequest_MissingAuth(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := GetUserFromRequest(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing Authorization header")
}

func TestGetUserFromRequest_InvalidAuthFormat(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	_, err := GetUserFromRequest(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid Authorization header")
}

func TestGetUserFromRequest_InvalidToken(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	_, err := GetUserFromRequest(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid token")
}

func TestGetUserFromRequest_NoSession(t *testing.T) {
	testutils.WithTestDB(t)

	// Generate a valid JWT but don't create a session
	accessTokenExpiresAt := time.Now().Add(config.Get().AuthAccessTokenExpiration).UTC()
	accessClaims := jwt.MapClaims{
		"exp":   accessTokenExpiresAt.Unix(),
		"iat":   time.Now().Unix(),
		"iss":   config.GetBootstrap().AppAuthIssuer,
		"aud":   config.Get().AuthAccessTokenAudience,
		"sub":   "some-user-id",
		"typ":   "Bearer",
		"sid":   xid.New().String(),
		"scope": "openid profile email",
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims)
	accessToken.Header["kid"] = config.GetBootstrap().AuthJwkCertKeyID
	signedToken, err := accessToken.SignedString(key.GetPrivateKey())
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+signedToken)
	_, err = GetUserFromRequest(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid session")
}

func TestGetUserFromRequest_Valid(t *testing.T) {
	testutils.WithTestDB(t)

	token, _ := setupAuthenticatedUser(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	user, err := GetUserFromRequest(req)
	assert.NoError(t, err)
	assert.NotNil(t, user)
}

// --- HandleCreateUser tests ---

func TestHandleCreateUser_Unauthorized(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodPost, "/users/create", nil)
	rr := httptest.NewRecorder()
	HandleCreateUser(rr, req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestHandleCreateUser_InvalidBody(t *testing.T) {
	testutils.WithTestDB(t)

	token, _ := setupAuthenticatedUser(t)
	req := httptest.NewRequest(http.MethodPost, "/users/create", bytes.NewBufferString("not-json"))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	HandleCreateUser(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid request payload")
}

func TestHandleCreateUser_ValidationError(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.ValidationMinUsernameLength = 3
		config.Values.ValidationMaxUsernameLength = 50
		config.Values.ValidationMinPasswordLength = 6
		config.Values.ValidationMaxPasswordLength = 100
		config.Values.ProfileFieldEmail = "hidden"
	})

	token, _ := setupAuthenticatedUser(t)
	body, _ := json.Marshal(UserCreateRequest{
		Username: "ab",
		Password: "password123",
	})
	req := httptest.NewRequest(http.MethodPost, "/users/create", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	HandleCreateUser(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "User validation error")
}

func TestHandleCreateUser_Success(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.ValidationMinUsernameLength = 3
		config.Values.ValidationMaxUsernameLength = 50
		config.Values.ValidationMinPasswordLength = 6
		config.Values.ValidationMaxPasswordLength = 100
		config.Values.ProfileFieldEmail = "hidden"
	})

	token, _ := setupAuthenticatedUser(t)
	body, _ := json.Marshal(UserCreateRequest{
		Username: "newuser",
		Password: "password123",
		Email:    "new@example.com",
	})
	req := httptest.NewRequest(http.MethodPost, "/users/create", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	HandleCreateUser(rr, req)
	assert.Equal(t, http.StatusCreated, rr.Code)
	assert.Contains(t, rr.Body.String(), "newuser")
}

func TestHandleCreateUser_UsernameIsEmail(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.ValidationMinUsernameLength = 3
		config.Values.ValidationMaxUsernameLength = 50
		config.Values.ValidationMinPasswordLength = 6
		config.Values.ValidationMaxPasswordLength = 100
		config.Values.ProfileFieldEmail = "is_username"
	})

	token, _ := setupAuthenticatedUser(t)
	body, _ := json.Marshal(UserCreateRequest{
		Username: "user@example.com",
		Password: "password123",
	})
	req := httptest.NewRequest(http.MethodPost, "/users/create", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	HandleCreateUser(rr, req)
	assert.Equal(t, http.StatusCreated, rr.Code)
	// When UsernameIsEmail is true and Email is empty, email should be set to username
	assert.Contains(t, rr.Body.String(), "user@example.com")
}

func TestHandleCreateUser_DuplicateUser(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.ValidationMinUsernameLength = 3
		config.Values.ValidationMaxUsernameLength = 50
		config.Values.ValidationMinPasswordLength = 6
		config.Values.ValidationMaxPasswordLength = 100
		config.Values.ProfileFieldEmail = "hidden"
	})

	token, _ := setupAuthenticatedUser(t)

	// Create first user
	body, _ := json.Marshal(UserCreateRequest{
		Username: "dupeuser",
		Password: "password123",
	})
	req := httptest.NewRequest(http.MethodPost, "/users/create", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	HandleCreateUser(rr, req)
	assert.Equal(t, http.StatusCreated, rr.Code)

	// Create duplicate user
	body, _ = json.Marshal(UserCreateRequest{
		Username: "dupeuser",
		Password: "password456",
	})
	req = httptest.NewRequest(http.MethodPost, "/users/create", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr = httptest.NewRecorder()
	HandleCreateUser(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Contains(t, rr.Body.String(), "User creation error")
}

// --- HandleGetUser tests ---

func TestHandleGetUser_Unauthorized(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/users?id=test", nil)
	rr := httptest.NewRecorder()
	HandleGetUser(rr, req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestHandleGetUser_MissingID(t *testing.T) {
	testutils.WithTestDB(t)

	token, _ := setupAuthenticatedUser(t)
	req := httptest.NewRequest(http.MethodGet, "/users", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	HandleGetUser(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Missing user id")
}

func TestHandleGetUser_NotFound(t *testing.T) {
	testutils.WithTestDB(t)

	token, _ := setupAuthenticatedUser(t)
	req := httptest.NewRequest(http.MethodGet, "/users?id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	HandleGetUser(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandleGetUser_Success(t *testing.T) {
	testutils.WithTestDB(t)

	token, userID := setupAuthenticatedUser(t)
	req := httptest.NewRequest(http.MethodGet, "/users?id="+userID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	HandleGetUser(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), userID)
}

// --- HandleUpdateUser tests ---

func TestHandleUpdateUser_Unauthorized(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodPut, "/users?id=test", nil)
	rr := httptest.NewRecorder()
	HandleUpdateUser(rr, req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestHandleUpdateUser_MissingID(t *testing.T) {
	testutils.WithTestDB(t)

	token, _ := setupAuthenticatedUser(t)
	req := httptest.NewRequest(http.MethodPut, "/users", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	HandleUpdateUser(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Missing user id")
}

func TestHandleUpdateUser_InvalidBody(t *testing.T) {
	testutils.WithTestDB(t)

	token, _ := setupAuthenticatedUser(t)
	req := httptest.NewRequest(http.MethodPut, "/users?id=test", bytes.NewBufferString("not-json"))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	HandleUpdateUser(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid request payload")
}

func TestHandleUpdateUser_ValidationError(t *testing.T) {
	testutils.WithTestDB(t)

	token, _ := setupAuthenticatedUser(t)
	body, _ := json.Marshal(UserUpdateRequest{
		Email: "not-an-email",
	})
	req := httptest.NewRequest(http.MethodPut, "/users?id=test", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	HandleUpdateUser(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleUpdateUser_Success(t *testing.T) {
	testutils.WithTestDB(t)

	token, userID := setupAuthenticatedUser(t)
	body, _ := json.Marshal(UserUpdateRequest{
		Email: "updated@example.com",
		Role:  "user",
	})
	req := httptest.NewRequest(http.MethodPut, "/users?id="+userID, bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	HandleUpdateUser(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "updated@example.com")
}

// --- HandleDeleteUser tests ---

func TestHandleDeleteUser_Unauthorized(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodDelete, "/users?id=test", nil)
	rr := httptest.NewRecorder()
	HandleDeleteUser(rr, req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestHandleDeleteUser_MissingID(t *testing.T) {
	testutils.WithTestDB(t)

	token, _ := setupAuthenticatedUser(t)
	req := httptest.NewRequest(http.MethodDelete, "/users", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	HandleDeleteUser(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Missing user id")
}

func TestHandleDeleteUser_Success(t *testing.T) {
	testutils.WithTestDB(t)

	token, _ := setupAuthenticatedUser(t)

	// Create a user to deactivate
	targetUserID := xid.New().String()
	_, err := db.GetDB().Exec(`
		INSERT INTO users (id, username, email, password) VALUES (?, ?, ?, ?)
	`, targetUserID, "deleteuser", "delete@example.com", "hashedpassword")
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodDelete, "/users?id="+targetUserID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	HandleDeleteUser(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "deleted")

	// User should still exist (soft delete) but have deactivated_at set
	var deactivatedAt *string
	row := db.GetDB().QueryRow(`SELECT deactivated_at FROM users WHERE id = ?`, targetUserID)
	err = row.Scan(&deactivatedAt)
	assert.NoError(t, err)
	assert.NotNil(t, deactivatedAt)
}

func TestHandleListUsers_Extra(t *testing.T) {
	testutils.WithTestDB(t)
	token, _ := setupAuthenticatedUser(t)

	// Add more users
	_, _ = CreateUser("u1", "p1", "e1@test.com")
	_, _ = CreateUser("u2", "p2", "e2@test.com")

	req := httptest.NewRequest(http.MethodGet, "/users/list", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	HandleListUsers(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "u1")
	assert.Contains(t, rr.Body.String(), "u2")
}

func TestHandleUnlockUser_Extra(t *testing.T) {
	testutils.WithTestDB(t)
	token, _ := setupAuthenticatedUser(t)

	// Create a locked user
	targetUserID := xid.New().String()
	_, _ = db.GetDB().Exec(`
		INSERT INTO users (id, username, email, password, locked_until) 
		VALUES (?, 'lockeduser', 'locked@test.com', 'pass', datetime('now', '+1 hour'))
	`, targetUserID)

	req := httptest.NewRequest(http.MethodPost, "/users/unlock?id="+targetUserID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	HandleUnlockUser(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "lockeduser")

	// Verify unlocked
	var lockedUntil *string
	_ = db.GetDB().QueryRow("SELECT locked_until FROM users WHERE id = ?", targetUserID).Scan(&lockedUntil)
	assert.Nil(t, lockedUntil)
}

func TestHandleUnlockUser_Errors_Extra(t *testing.T) {
	testutils.WithTestDB(t)
	token, _ := setupAuthenticatedUser(t)

	// Method not allowed
	req := httptest.NewRequest(http.MethodGet, "/users/unlock?id=123", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	HandleUnlockUser(rr, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)

	// Missing user_id
	req = httptest.NewRequest(http.MethodPost, "/users/unlock", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr = httptest.NewRecorder()
	HandleUnlockUser(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleUserAdminEndpoint_Extra(t *testing.T) {
	testutils.WithTestDB(t)
	token, _ := setupAuthenticatedUser(t)

	// GET -> HandleListUsers
	req := httptest.NewRequest(http.MethodGet, "/admin/api/users", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	HandleUserAdminEndpoint(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	// POST -> HandleCreateUser
	testutils.WithConfigOverride(t, func() {
		config.Values.ProfileFieldEmail = "hidden"
	})
	body, _ := json.Marshal(UserCreateRequest{Username: "newadmin", Password: "password123"})
	req = httptest.NewRequest(http.MethodPost, "/admin/api/users", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr = httptest.NewRecorder()
	HandleUserAdminEndpoint(rr, req)
	assert.Equal(t, http.StatusCreated, rr.Code)

	// Method Not Allowed
	req = httptest.NewRequest(http.MethodPatch, "/admin/api/users", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr = httptest.NewRecorder()
	HandleUserAdminEndpoint(rr, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}

func generateTestAdminToken(userID string) (string, error) {
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
	if err != nil {
		return "", err
	}

	// Create session so the session check passes
	_, err = db.GetDB().Exec(`
		INSERT INTO sessions (id, user_id, access_token, refresh_token, user_agent, ip_address, location, last_activity_at, created_at, expires_at, deactivated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, sessionID, userID, signedToken, "", "agent", "127.0.0.1", "location", time.Now(), time.Now(), accessTokenExpiresAt, nil)
	if err != nil {
		return "", err
	}

	return signedToken, err
}

func TestHandleUserAdminEndpoint(t *testing.T) {
	testutils.WithTestDB(t)

	adminUser, _ := CreateUser("admin", "pass123", "admin@example.com")
	_ = UpdateUser(adminUser.ID, UserUpdateRequest{Email: adminUser.Email, Role: "admin"})
	token, _ := generateTestAdminToken(adminUser.ID)

	_, _ = CreateUser("user1", "pass123", "user1@example.com")
	_, _ = CreateUser("user2", "pass123", "user2@example.com")

	// Test GET /admin/api/users (List)
	req := httptest.NewRequest(http.MethodGet, "/admin/api/users", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	HandleUserAdminEndpoint(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp model.ApiResponse[[]UserResponse]
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Len(t, resp.Data, 3) // admin + user1 + user2

	// Test GET /admin/api/users?id=... (Get single)
	u1, _ := UserByUsername("user1")
	req = httptest.NewRequest(http.MethodGet, "/admin/api/users?id="+u1.ID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr = httptest.NewRecorder()
	HandleUserAdminEndpoint(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var singleResp model.ApiResponse[UserResponse]
	err = json.Unmarshal(rr.Body.Bytes(), &singleResp)
	assert.NoError(t, err)
	assert.Equal(t, "user1", singleResp.Data.Username)

	// Test PUT /admin/api/users?id=... (Update)
	body := `{"email": "new@example.com", "role": "admin"}`
	req = httptest.NewRequest(http.MethodPut, "/admin/api/users?id="+u1.ID, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr = httptest.NewRecorder()
	HandleUserAdminEndpoint(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	u1, _ = UserByID(u1.ID)
	assert.Equal(t, "new@example.com", u1.Email)
	assert.Equal(t, "admin", u1.Role)

	// Test DELETE /admin/api/users?id=... (Delete)
	req = httptest.NewRequest(http.MethodDelete, "/admin/api/users?id="+u1.ID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr = httptest.NewRecorder()
	HandleUserAdminEndpoint(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	_, err = UserByID(u1.ID)
	assert.Error(t, err) // Should be not found
}

func TestHandleUnlockUser(t *testing.T) {
	testutils.WithTestDB(t)
	adminUser, _ := CreateUser("admin", "pass123", "admin@example.com")
	_ = UpdateUser(adminUser.ID, UserUpdateRequest{Email: adminUser.Email, Role: "admin"})
	token, _ := generateTestAdminToken(adminUser.ID)

	u, _ := CreateUser("lockeduser", "pass123", "locked@example.com")
	
	req := httptest.NewRequest(http.MethodPost, "/admin/api/users/unlock?id="+u.ID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	HandleUnlockUser(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}
