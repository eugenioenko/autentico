package user

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/key"
	"github.com/eugenioenko/autentico/pkg/model"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/rs/xid"

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

// --- HandleCreateUser tests ---

func TestHandleCreateUser_InvalidBody(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodPost, "/admin/api/users", bytes.NewBufferString("not-json"))
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
	})

	body, _ := json.Marshal(UserCreateRequest{
		Username: "ab", // too short
		Password: "password123",
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/api/users", bytes.NewBuffer(body))
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
	})

	body, _ := json.Marshal(UserCreateRequest{
		Username: "newuser",
		Password: "password123",
		Email:    "new@example.com",
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/api/users", bytes.NewBuffer(body))
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
		config.Values.ProfileFieldEmail = "is_username"
	})

	body, _ := json.Marshal(UserCreateRequest{
		Username: "user@example.com",
		Password: "password123",
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/api/users", bytes.NewBuffer(body))
	rr := httptest.NewRecorder()
	HandleCreateUser(rr, req)
	assert.Equal(t, http.StatusCreated, rr.Code)
	assert.Contains(t, rr.Body.String(), "user@example.com")
}

func TestHandleCreateUser_DuplicateUser(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.ValidationMinUsernameLength = 3
		config.Values.ValidationMaxUsernameLength = 50
		config.Values.ValidationMinPasswordLength = 6
	})

	body, _ := json.Marshal(UserCreateRequest{
		Username: "dupeuser",
		Password: "password123",
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/api/users", bytes.NewBuffer(body))
	rr := httptest.NewRecorder()
	HandleCreateUser(rr, req)
	assert.Equal(t, http.StatusCreated, rr.Code)

	// Create duplicate user
	body, _ = json.Marshal(UserCreateRequest{
		Username: "dupeuser",
		Password: "password456",
	})
	req = httptest.NewRequest(http.MethodPost, "/admin/api/users", bytes.NewBuffer(body))
	rr = httptest.NewRecorder()
	HandleCreateUser(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "already exists")
}

// --- HandleGetUser tests ---

func TestHandleGetUser_MissingID(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/users/", nil)
	rr := httptest.NewRecorder()
	HandleGetUser(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Missing user id")
}

func TestHandleGetUser_NotFound(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/users/nonexistent", nil)
	req.SetPathValue("id", "nonexistent")
	rr := httptest.NewRecorder()
	HandleGetUser(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandleGetUser_Success(t *testing.T) {
	testutils.WithTestDB(t)

	_, userID := setupAuthenticatedUser(t)
	req := httptest.NewRequest(http.MethodGet, "/admin/api/users/"+userID, nil)
	req.SetPathValue("id", userID)
	rr := httptest.NewRecorder()
	HandleGetUser(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), userID)
}

// --- HandleUpdateUser tests ---

func TestHandleUpdateUser_MissingID(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodPut, "/admin/api/users/", nil)
	rr := httptest.NewRecorder()
	HandleUpdateUser(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Missing user id")
}

func TestHandleUpdateUser_InvalidBody(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodPut, "/admin/api/users/test", bytes.NewBufferString("not-json"))
	req.SetPathValue("id", "test")
	rr := httptest.NewRecorder()
	HandleUpdateUser(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid request payload")
}

func TestHandleUpdateUser_ValidationError(t *testing.T) {
	testutils.WithTestDB(t)

	body, _ := json.Marshal(UserUpdateRequest{
		Email: "not-an-email",
	})
	req := httptest.NewRequest(http.MethodPut, "/admin/api/users/test", bytes.NewBuffer(body))
	req.SetPathValue("id", "test")
	rr := httptest.NewRecorder()
	HandleUpdateUser(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleUpdateUser_Success(t *testing.T) {
	testutils.WithTestDB(t)

	_, userID := setupAuthenticatedUser(t)
	body, _ := json.Marshal(UserUpdateRequest{
		Email: "updated@example.com",
		Role:  "user",
	})
	req := httptest.NewRequest(http.MethodPut, "/admin/api/users/"+userID, bytes.NewBuffer(body))
	req.SetPathValue("id", userID)
	rr := httptest.NewRecorder()
	HandleUpdateUser(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "updated@example.com")
}

// --- HandleDeleteUser tests ---

func TestHandleDeleteUser_MissingID(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodDelete, "/admin/api/users/", nil)
	rr := httptest.NewRecorder()
	HandleDeleteUser(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Missing user id")
}

func TestHandleDeleteUser_Success(t *testing.T) {
	testutils.WithTestDB(t)

	targetUserID := xid.New().String()
	_, err := db.GetDB().Exec(`
		INSERT INTO users (id, username, email, password) VALUES (?, ?, ?, ?)
	`, targetUserID, "deleteuser", "delete@example.com", "hashedpassword")
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodDelete, "/admin/api/users/"+targetUserID, nil)
	req.SetPathValue("id", targetUserID)
	rr := httptest.NewRecorder()
	HandleDeleteUser(rr, req)
	assert.Equal(t, http.StatusNoContent, rr.Code)

	// User should be permanently deleted
	var count int
	_ = db.GetDB().QueryRow(`SELECT COUNT(*) FROM users WHERE id = ?`, targetUserID).Scan(&count)
	assert.Equal(t, 0, count)
}

// --- HandleListUsers tests ---

func TestHandleListUsers_Extra(t *testing.T) {
	testutils.WithTestDB(t)

	_, _ = CreateUser("u1", "p1", "e1@test.com")
	_, _ = CreateUser("u2", "p2", "e2@test.com")

	req := httptest.NewRequest(http.MethodGet, "/admin/api/users", nil)
	rr := httptest.NewRecorder()
	HandleListUsers(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "u1")
	assert.Contains(t, rr.Body.String(), "u2")
}

func TestHandleListUsers_GroupFilter(t *testing.T) {
	testutils.WithTestDB(t)

	u1, _ := CreateUser("gf-user1", "p1", "gf1@test.com")
	_, _ = CreateUser("gf-user2", "p2", "gf2@test.com")

	_, err := db.GetDB().Exec(`INSERT INTO groups (id, name, description) VALUES ('g1', 'test-group', 'test')`)
	assert.NoError(t, err)
	_, err = db.GetDB().Exec(`INSERT INTO user_groups (user_id, group_id) VALUES (?, 'g1')`, u1.ID)
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/users?group=test-group", nil)
	rr := httptest.NewRecorder()
	HandleListUsers(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "gf-user1")
	assert.NotContains(t, rr.Body.String(), "gf-user2")
}

// --- HandleUnlockUser tests ---

func TestHandleUnlockUser_MissingID(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodPost, "/admin/api/users//unlock", nil)
	rr := httptest.NewRecorder()
	HandleUnlockUser(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Missing user id")
}

func TestHandleUnlockUser_Success(t *testing.T) {
	testutils.WithTestDB(t)

	targetUserID := xid.New().String()
	_, _ = db.GetDB().Exec(`
		INSERT INTO users (id, username, email, password, locked_until)
		VALUES (?, 'lockeduser', 'locked@test.com', 'pass', datetime('now', '+1 hour'))
	`, targetUserID)

	req := httptest.NewRequest(http.MethodPost, "/admin/api/users/"+targetUserID+"/unlock", nil)
	req.SetPathValue("id", targetUserID)
	rr := httptest.NewRecorder()
	HandleUnlockUser(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "lockeduser")

	var lockedUntil *string
	_ = db.GetDB().QueryRow("SELECT locked_until FROM users WHERE id = ?", targetUserID).Scan(&lockedUntil)
	assert.Nil(t, lockedUntil)
}

// --- HandleUserAdmin integration tests ---

func TestHandleUserAdmin(t *testing.T) {
	testutils.WithTestDB(t)

	_, _ = CreateUser("user1", "pass123", "user1@example.com")
	_, _ = CreateUser("user2", "pass123", "user2@example.com")

	// List users
	req := httptest.NewRequest(http.MethodGet, "/admin/api/users", nil)
	rr := httptest.NewRecorder()
	HandleListUsers(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	var listResp struct {
		Data struct {
			Items []UserResponse `json:"items"`
			Total int            `json:"total"`
		} `json:"data"`
	}
	err := json.Unmarshal(rr.Body.Bytes(), &listResp)
	assert.NoError(t, err)
	assert.Len(t, listResp.Data.Items, 2)
	assert.Equal(t, 2, listResp.Data.Total)

	// Get single user
	u1, _ := UserByUsername("user1")
	req = httptest.NewRequest(http.MethodGet, "/admin/api/users/"+u1.ID, nil)
	req.SetPathValue("id", u1.ID)
	rr = httptest.NewRecorder()
	HandleGetUser(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	var singleResp model.ApiResponse[UserResponse]
	err = json.Unmarshal(rr.Body.Bytes(), &singleResp)
	assert.NoError(t, err)
	assert.Equal(t, "user1", singleResp.Data.Username)

	// Update user
	body := `{"email": "new@example.com", "role": "admin"}`
	req = httptest.NewRequest(http.MethodPut, "/admin/api/users/"+u1.ID, strings.NewReader(body))
	req.SetPathValue("id", u1.ID)
	rr = httptest.NewRecorder()
	HandleUpdateUser(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	u1, _ = UserByID(u1.ID)
	assert.Equal(t, "new@example.com", u1.Email)

	// Delete user
	req = httptest.NewRequest(http.MethodDelete, "/admin/api/users/"+u1.ID, nil)
	req.SetPathValue("id", u1.ID)
	rr = httptest.NewRecorder()
	HandleDeleteUser(rr, req)
	assert.Equal(t, http.StatusNoContent, rr.Code)
}

func TestHandleCreateUser_AdminFlow(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.ProfileFieldEmail = "hidden"
	})

	body, _ := json.Marshal(UserCreateRequest{Username: "newadmin", Password: "password123"})
	req := httptest.NewRequest(http.MethodPost, "/admin/api/users", bytes.NewBuffer(body))
	rr := httptest.NewRecorder()
	HandleCreateUser(rr, req)
	assert.Equal(t, http.StatusCreated, rr.Code)
}
