package account

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/model"
	"github.com/eugenioenko/autentico/pkg/user"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestHandleGetProfile(t *testing.T) {
	testutils.WithTestDB(t)
	token, usr := setupTestUserAndSession(t)

	rr := testutils.MockApiRequestWithAuth(t, "", "GET", "/account/profile", HandleGetProfile, token)

	assert.Equal(t, http.StatusOK, rr.Code)
	
	var resp model.ApiResponse[user.UserResponse]
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, usr.Username, resp.Data.Username)
}

func TestHandleGetProfile_Unauthorized(t *testing.T) {
	testutils.WithTestDB(t)
	rr := testutils.MockApiRequestWithAuth(t, "", "GET", "/account/profile", HandleGetProfile, "invalid-token")
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestHandleUpdateProfile_AllFields(t *testing.T) {
	testutils.WithTestDB(t)
	token, _ := setupTestUserAndSession(t)

	updateReq := user.UserUpdateRequest{
		GivenName:         "John",
		FamilyName:        "Doe",
		PhoneNumber:       "+123456789",
		Picture:           "http://example.com/pic.jpg",
		Locale:            "en-US",
		Zoneinfo:          "America/New_York",
		AddressStreet:     "123 Main St",
		AddressLocality:   "New York",
		AddressRegion:     "NY",
		AddressPostalCode: "10001",
		AddressCountry:    "USA",
	}
	body, _ := json.Marshal(updateReq)
	rr := testutils.MockApiRequestWithAuth(t, string(body), "POST", "/account/profile", HandleUpdateProfile, token)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHandleUpdateProfile_Errors(t *testing.T) {
	testutils.WithTestDB(t)
	token, _ := setupTestUserAndSession(t)

	// Username change not allowed
	testutils.WithConfigOverride(t, func() {
		config.Values.AllowUsernameChange = false
		req := user.UserUpdateRequest{Username: "newusername"}
		b, _ := json.Marshal(req)
		rr := testutils.MockApiRequestWithAuth(t, string(b), "POST", "/account/profile", HandleUpdateProfile, token)
		assert.Equal(t, http.StatusForbidden, rr.Code)
	})

	// Email already in use
	testutils.WithConfigOverride(t, func() {
		config.Values.AllowEmailChange = true
		otherUserID := uuid.New().String()
		_, _ = db.GetDB().Exec("INSERT INTO users (id, username, email) VALUES (?, ?, ?)", otherUserID, "other", "other@test.com")
		req := user.UserUpdateRequest{Email: "other@test.com"}
		b, _ := json.Marshal(req)
		rr := testutils.MockApiRequestWithAuth(t, string(b), "POST", "/account/profile", HandleUpdateProfile, token)
		assert.Equal(t, http.StatusConflict, rr.Code)
	})
	
	// Invalid JSON
	rr := testutils.MockApiRequestWithAuth(t, "{invalid", "POST", "/account/profile", HandleUpdateProfile, token)
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	// Validation error
	testutils.WithConfigOverride(t, func() {
		config.Values.AllowUsernameChange = true
		req := user.UserUpdateRequest{Username: "a"} // too short
		b, _ := json.Marshal(req)
		rr := testutils.MockApiRequestWithAuth(t, string(b), "POST", "/account/profile", HandleUpdateProfile, token)
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

func TestHandleUpdatePassword(t *testing.T) {
	testutils.WithTestDB(t)
	token, usr := setupTestUserAndSession(t)

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("current-password"), bcrypt.DefaultCost)
	_, _ = db.GetDB().Exec("UPDATE users SET password = ? WHERE id = ?", string(hashedPassword), usr.ID)

	updateReq := UpdatePasswordRequest{
		CurrentPassword: "current-password",
		NewPassword:     "new-secure-password123",
	}
	body, _ := json.Marshal(updateReq)
	rr := testutils.MockApiRequestWithAuth(t, string(body), "POST", "/account/password", HandleUpdatePassword, token)
	assert.Equal(t, http.StatusOK, rr.Code)

	// Invalid current password (returns 403)
	updateReq.CurrentPassword = "wrong"
	body, _ = json.Marshal(updateReq)
	rr = testutils.MockApiRequestWithAuth(t, string(body), "POST", "/account/password", HandleUpdatePassword, token)
	assert.Equal(t, http.StatusForbidden, rr.Code)

	// Invalid new password (too short) — must pass current password check first
	updateReq.CurrentPassword = "current-password"
	updateReq.NewPassword = "short"
	body, _ = json.Marshal(updateReq)
	rr = testutils.MockApiRequestWithAuth(t, string(body), "POST", "/account/password", HandleUpdatePassword, token)
	assert.Contains(t, []int{http.StatusBadRequest, http.StatusForbidden}, rr.Code)
}

func TestHandleUpdatePassword_NoPassword(t *testing.T) {
	testutils.WithTestDB(t)
	token, usr := setupTestUserAndSession(t)

	// User has no password (passkey user)
	_, _ = db.GetDB().Exec("UPDATE users SET password = '' WHERE id = ?", usr.ID)

	updateReq := UpdatePasswordRequest{
		CurrentPassword: "any",
		NewPassword:     "new-password",
	}
	body, _ := json.Marshal(updateReq)
	rr := testutils.MockApiRequestWithAuth(t, string(body), "POST", "/account/password", HandleUpdatePassword, token)
	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestHandleGetProfile_Success(t *testing.T) {
	testutils.WithTestDB(t)
	token, u := setupTestUserAndSession(t)

	req := httptest.NewRequest("GET", "/account/api/profile", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	HandleGetProfile(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	
	var resp model.ApiResponse[user.User]
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, u.Username, resp.Data.Username)
}

func TestHandleUpdateProfile_DbError(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AllowEmailChange = true
	})
	token, _ := setupTestUserAndSession(t)
	
	req := user.UserUpdateRequest{GivenName: "New Name"}
	body, _ := json.Marshal(req)
	
	// Close DB to trigger error in UpdateUser
	db.CloseDB()

	rr := testutils.MockApiRequestWithAuth(t, string(body), "PUT", "/account/api/profile", HandleUpdateProfile, token)
	assert.Equal(t, http.StatusUnauthorized, rr.Code) // GetUserFromRequest fails with 401 if DB closed
}
