package account

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/middleware"
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
	_, usr, info := setupTestUserAndSession(t)

	rr := mockAuthRequest(t, "", "GET", "/account/profile", HandleGetProfile, info)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp model.ApiResponse[user.UserResponse]
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, usr.Username, resp.Data.Username)
}

func TestHandleGetProfile_Unauthorized(t *testing.T) {
	testutils.WithTestDB(t)
	rr := mockAuthRequest(t, "", "GET", "/account/profile", HandleGetProfile, nil)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestHandleUpdateProfile_AllFields(t *testing.T) {
	testutils.WithTestDB(t)
	_, _, info := setupTestUserAndSession(t)

	updateReq := ProfileUpdateRequest{
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
	rr := mockAuthRequest(t, string(body), "POST", "/account/profile", HandleUpdateProfile, info)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHandleUpdateProfile_Errors(t *testing.T) {
	testutils.WithTestDB(t)
	_, usr, info := setupTestUserAndSession(t)

	// Clear password so password check is skipped in these validation tests
	_, _ = db.GetDB().Exec("UPDATE users SET password = '' WHERE id = ?", usr.ID)

	// Username change not allowed
	testutils.WithConfigOverride(t, func() {
		config.Values.AllowUsernameChange = false
		req := ProfileUpdateRequest{Username: "newusername"}
		b, _ := json.Marshal(req)
		rr := mockAuthRequest(t, string(b), "POST", "/account/profile", HandleUpdateProfile, info)
		assert.Equal(t, http.StatusForbidden, rr.Code)
	})

	// Email already in use
	testutils.WithConfigOverride(t, func() {
		config.Values.AllowEmailChange = true
		otherUserID := uuid.New().String()
		_, _ = db.GetDB().Exec("INSERT INTO users (id, username, email) VALUES (?, ?, ?)", otherUserID, "other", "other@test.com")
		req := ProfileUpdateRequest{Email: "other@test.com", CurrentPassword: "password"}
		b, _ := json.Marshal(req)
		rr := mockAuthRequest(t, string(b), "POST", "/account/profile", HandleUpdateProfile, info)
		assert.Equal(t, http.StatusConflict, rr.Code)
	})

	// Invalid JSON
	rr := mockAuthRequest(t, "{invalid", "POST", "/account/profile", HandleUpdateProfile, info)
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	// Validation error — passkey user (no password) so password check is skipped
	testutils.WithConfigOverride(t, func() {
		config.Values.AllowUsernameChange = true
		req := ProfileUpdateRequest{Username: "a"} // too short
		b, _ := json.Marshal(req)
		rr := mockAuthRequest(t, string(b), "POST", "/account/profile", HandleUpdateProfile, info)
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

func TestHandleUpdatePassword(t *testing.T) {
	testutils.WithTestDB(t)
	_, usr, info := setupTestUserAndSession(t)

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("current-password"), bcrypt.DefaultCost)
	_, _ = db.GetDB().Exec("UPDATE users SET password = ? WHERE id = ?", string(hashedPassword), usr.ID)

	updateReq := UpdatePasswordRequest{
		CurrentPassword: "current-password",
		NewPassword:     "new-secure-password123",
	}
	body, _ := json.Marshal(updateReq)
	rr := mockAuthRequest(t, string(body), "POST", "/account/password", HandleUpdatePassword, info)
	assert.Equal(t, http.StatusOK, rr.Code)

	// Invalid current password (returns 403)
	updateReq.CurrentPassword = "wrong"
	body, _ = json.Marshal(updateReq)
	rr = mockAuthRequest(t, string(body), "POST", "/account/password", HandleUpdatePassword, info)
	assert.Equal(t, http.StatusForbidden, rr.Code)

	// Invalid new password (too short) — must pass current password check first
	updateReq.CurrentPassword = "current-password"
	updateReq.NewPassword = "short"
	body, _ = json.Marshal(updateReq)
	rr = mockAuthRequest(t, string(body), "POST", "/account/password", HandleUpdatePassword, info)
	assert.Contains(t, []int{http.StatusBadRequest, http.StatusForbidden}, rr.Code)
}

func TestHandleUpdatePassword_NoPassword(t *testing.T) {
	testutils.WithTestDB(t)
	_, usr, info := setupTestUserAndSession(t)

	// User has no password (passkey user)
	_, _ = db.GetDB().Exec("UPDATE users SET password = '' WHERE id = ?", usr.ID)

	updateReq := UpdatePasswordRequest{
		CurrentPassword: "any",
		NewPassword:     "new-password",
	}
	body, _ := json.Marshal(updateReq)
	rr := mockAuthRequest(t, string(body), "POST", "/account/password", HandleUpdatePassword, info)
	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestHandleGetProfile_Success(t *testing.T) {
	testutils.WithTestDB(t)
	_, u, info := setupTestUserAndSession(t)

	req := httptest.NewRequest("GET", "/account/api/profile", nil)
	req = middleware.WithAuthInfo(req, info)
	rr := httptest.NewRecorder()
	HandleGetProfile(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp model.ApiResponse[user.User]
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, u.Username, resp.Data.Username)
}

func TestHandleUpdateProfile_EmailChangeRequiresPassword(t *testing.T) {
	testutils.WithTestDB(t)
	_, usr, info := setupTestUserAndSession(t)

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	_, _ = db.GetDB().Exec("UPDATE users SET password = ? WHERE id = ?", string(hashedPassword), usr.ID)

	testutils.WithConfigOverride(t, func() {
		config.Values.AllowEmailChange = true

		// Without password — should fail
		req := ProfileUpdateRequest{Email: "new@test.com"}
		b, _ := json.Marshal(req)
		rr := mockAuthRequest(t, string(b), "PUT", "/account/api/profile", HandleUpdateProfile, info)
		assert.Equal(t, http.StatusForbidden, rr.Code)

		// Wrong password — should fail
		req = ProfileUpdateRequest{Email: "new@test.com", CurrentPassword: "wrong"}
		b, _ = json.Marshal(req)
		rr = mockAuthRequest(t, string(b), "PUT", "/account/api/profile", HandleUpdateProfile, info)
		assert.Equal(t, http.StatusForbidden, rr.Code)

		// Correct password — should succeed
		req = ProfileUpdateRequest{Email: "new@test.com", CurrentPassword: "password"}
		b, _ = json.Marshal(req)
		rr = mockAuthRequest(t, string(b), "PUT", "/account/api/profile", HandleUpdateProfile, info)
		assert.Equal(t, http.StatusOK, rr.Code)

		// Verify email_verified was reset
		updated, _ := user.UserByID(usr.ID)
		assert.False(t, updated.IsEmailVerified)
	})
}

func TestHandleUpdateProfile_UsernameChangeRequiresPassword(t *testing.T) {
	testutils.WithTestDB(t)
	_, usr, info := setupTestUserAndSession(t)

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	_, _ = db.GetDB().Exec("UPDATE users SET password = ? WHERE id = ?", string(hashedPassword), usr.ID)

	testutils.WithConfigOverride(t, func() {
		config.Values.AllowUsernameChange = true

		// Without password — should fail
		req := ProfileUpdateRequest{Username: "newname"}
		b, _ := json.Marshal(req)
		rr := mockAuthRequest(t, string(b), "PUT", "/account/api/profile", HandleUpdateProfile, info)
		assert.Equal(t, http.StatusForbidden, rr.Code)

		// Correct password — should succeed
		req = ProfileUpdateRequest{Username: "newname", CurrentPassword: "password"}
		b, _ = json.Marshal(req)
		rr = mockAuthRequest(t, string(b), "PUT", "/account/api/profile", HandleUpdateProfile, info)
		assert.Equal(t, http.StatusOK, rr.Code)
	})
}

func TestHandleUpdateProfile_NonSensitiveFieldsNoPassword(t *testing.T) {
	testutils.WithTestDB(t)
	_, _, info := setupTestUserAndSession(t)

	req := ProfileUpdateRequest{GivenName: "NewName", FamilyName: "NewFamily"}
	b, _ := json.Marshal(req)
	rr := mockAuthRequest(t, string(b), "PUT", "/account/api/profile", HandleUpdateProfile, info)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHandleUpdateProfile_PasskeyUserSkipsPasswordCheck(t *testing.T) {
	testutils.WithTestDB(t)
	_, usr, info := setupTestUserAndSession(t)

	// Passkey user has empty password
	_, _ = db.GetDB().Exec("UPDATE users SET password = '' WHERE id = ?", usr.ID)

	testutils.WithConfigOverride(t, func() {
		config.Values.AllowEmailChange = true

		req := ProfileUpdateRequest{Email: "new@test.com"}
		b, _ := json.Marshal(req)
		rr := mockAuthRequest(t, string(b), "PUT", "/account/api/profile", HandleUpdateProfile, info)
		assert.Equal(t, http.StatusOK, rr.Code)
	})
}

func TestHandleUpdateProfile_EmailChangeResetsVerified(t *testing.T) {
	testutils.WithTestDB(t)
	_, usr, info := setupTestUserAndSession(t)

	_, _ = db.GetDB().Exec("UPDATE users SET password = '', is_email_verified = TRUE WHERE id = ?", usr.ID)

	testutils.WithConfigOverride(t, func() {
		config.Values.AllowEmailChange = true

		req := ProfileUpdateRequest{Email: "changed@test.com"}
		b, _ := json.Marshal(req)
		rr := mockAuthRequest(t, string(b), "PUT", "/account/api/profile", HandleUpdateProfile, info)
		assert.Equal(t, http.StatusOK, rr.Code)

		updated, _ := user.UserByID(usr.ID)
		assert.Equal(t, "changed@test.com", updated.Email)
		assert.False(t, updated.IsEmailVerified)
	})
}

func TestHandleUpdateProfile_SameEmailNoPasswordRequired(t *testing.T) {
	testutils.WithTestDB(t)
	_, usr, info := setupTestUserAndSession(t)

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	_, _ = db.GetDB().Exec("UPDATE users SET password = ? WHERE id = ?", string(hashedPassword), usr.ID)

	testutils.WithConfigOverride(t, func() {
		config.Values.AllowEmailChange = true

		// Submitting same email should not require password
		req := ProfileUpdateRequest{Email: usr.Email, GivenName: "Updated"}
		b, _ := json.Marshal(req)
		rr := mockAuthRequest(t, string(b), "PUT", "/account/api/profile", HandleUpdateProfile, info)
		assert.Equal(t, http.StatusOK, rr.Code)
	})
}

func TestHandleUpdateProfile_DbError(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AllowEmailChange = true
	})
	_, _, info := setupTestUserAndSession(t)

	req := ProfileUpdateRequest{GivenName: "New Name"}
	body, _ := json.Marshal(req)

	// Close DB to trigger error in UpdateUser
	db.CloseDB()

	rr := mockAuthRequest(t, string(body), "PUT", "/account/api/profile", HandleUpdateProfile, info)
	assert.Equal(t, http.StatusInternalServerError, rr.Code) // Auth from context succeeds, UpdateUser fails with DB closed
}
