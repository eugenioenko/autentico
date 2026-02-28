package user

import (
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
		INSERT INTO sessions (id, user_id, access_token, refresh_token, user_agent, ip_address, device_id, location, last_activity_at, created_at, expires_at, deactivated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, sessionID, userID, signedToken, "", "agent", "127.0.0.1", "", "location", time.Now(), time.Now(), accessTokenExpiresAt, nil)
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
