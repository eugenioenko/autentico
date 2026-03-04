package account

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/model"
	"github.com/eugenioenko/autentico/pkg/user"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestHandleGetMfaStatus(t *testing.T) {
	testutils.WithTestDB(t)
	token, usr := setupTestUserAndSession(t)

	// Enabled
	_, _ = db.GetDB().Exec("UPDATE users SET totp_verified = TRUE WHERE id = ?", usr.ID)

	rr := testutils.MockApiRequestWithAuth(t, "", "GET", "/account/mfa/status", HandleGetMfaStatus, token)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHandleVerifyTotp(t *testing.T) {
	testutils.WithTestDB(t)
	token, usr := setupTestUserAndSession(t)

	_ = testutils.MockApiRequestWithAuth(t, "", "POST", "/account/mfa/totp/setup", HandleSetupTotp, token)
	
	currUser, _ := user.UserByID(usr.ID)
	secret := currUser.TotpSecret
	code, _ := totp.GenerateCode(secret, time.Now())

	verifyReq := TotpVerifyRequest{Code: code}
	body, _ := json.Marshal(verifyReq)
	rr := testutils.MockApiRequestWithAuth(t, string(body), "POST", "/account/mfa/totp/verify", HandleVerifyTotp, token)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHandleVerifyTotp_Errors(t *testing.T) {
	testutils.WithTestDB(t)
	token, usr := setupTestUserAndSession(t)

	// TOTP not initiated
	verifyReq := TotpVerifyRequest{Code: "000000"}
	body, _ := json.Marshal(verifyReq)
	rr := testutils.MockApiRequestWithAuth(t, string(body), "POST", "/account/mfa/totp/verify", HandleVerifyTotp, token)
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	// Invalid code
	_ = user.StoreTotpSecretPending(usr.ID, "dummy")
	rr = testutils.MockApiRequestWithAuth(t, string(body), "POST", "/account/mfa/totp/verify", HandleVerifyTotp, token)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleDeleteMfa(t *testing.T) {
	testutils.WithTestDB(t)
	token, usr := setupTestUserAndSession(t)

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	_, _ = db.GetDB().Exec("UPDATE users SET password = ? WHERE id = ?", string(hashedPassword), usr.ID)
	_, _ = db.GetDB().Exec("UPDATE users SET totp_verified = TRUE WHERE id = ?", usr.ID)

	deleteReq := DisableMfaRequest{CurrentPassword: "password"}
	body, _ := json.Marshal(deleteReq)
	rr := testutils.MockApiRequestWithAuth(t, string(body), "POST", "/account/mfa/delete", HandleDeleteMfa, token)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHandleDeleteMfa_NoPassword(t *testing.T) {
	testutils.WithTestDB(t)
	token, usr := setupTestUserAndSession(t)

	// User has no password
	_, _ = db.GetDB().Exec("UPDATE users SET password = '', totp_verified = TRUE WHERE id = ?", usr.ID)

	deleteReq := DisableMfaRequest{}
	body, _ := json.Marshal(deleteReq)
	rr := testutils.MockApiRequestWithAuth(t, string(body), "POST", "/account/mfa/delete", HandleDeleteMfa, token)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHandleDeleteMfa_InvalidJSON(t *testing.T) {
	testutils.WithTestDB(t)
	token, _ := setupTestUserAndSession(t)
	rr := testutils.MockApiRequestWithAuth(t, "{invalid", "POST", "/account/api/mfa/delete", HandleDeleteMfa, token)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleDeleteMfa_WrongPassword(t *testing.T) {
	testutils.WithTestDB(t)
	token, _ := setupTestUserAndSession(t)
	
	req := DisableMfaRequest{CurrentPassword: "wrong"}
	body, _ := json.Marshal(req)
	rr := testutils.MockApiRequestWithAuth(t, string(body), "POST", "/account/api/mfa/delete", HandleDeleteMfa, token)
	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestHandleMfaFlow(t *testing.T) {
	testutils.WithTestDB(t)
	token, u := setupTestUserAndSession(t)

	// Set a valid hashed password for AuthenticateUser to work
	hashed, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	_, _ = db.GetDB().Exec("UPDATE users SET password = ? WHERE id = ?", string(hashed), u.ID)

	// 1. Get MFA Status
	req := httptest.NewRequest("GET", "/account/api/mfa/status", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	HandleGetMfaStatus(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	
	var statusResp model.ApiResponse[MfaStatusResponse]
	err := json.Unmarshal(rr.Body.Bytes(), &statusResp)
	require.NoError(t, err)
	assert.False(t, statusResp.Data.TotpEnabled)

	// 2. Setup TOTP
	req = httptest.NewRequest("POST", "/account/api/mfa/totp/setup", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr = httptest.NewRecorder()
	HandleSetupTotp(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	
	var setupResp model.ApiResponse[TotpSetupResponse]
	err = json.Unmarshal(rr.Body.Bytes(), &setupResp)
	require.NoError(t, err)
	assert.NotEmpty(t, setupResp.Data.Secret)

	// 3. Verify TOTP (valid code)
	code, _ := totp.GenerateCode(setupResp.Data.Secret, time.Now())
	verifyReq := TotpVerifyRequest{Code: code}
	body, _ := json.Marshal(verifyReq)
	rr = testutils.MockApiRequestWithAuth(t, string(body), "POST", "/account/api/mfa/totp/verify", HandleVerifyTotp, token)
	assert.Equal(t, http.StatusOK, rr.Code)

	// 4. Verify status again
	rr = httptest.NewRecorder()
	HandleGetMfaStatus(rr, req) // reusing req
	err = json.Unmarshal(rr.Body.Bytes(), &statusResp)
	require.NoError(t, err)
	assert.True(t, statusResp.Data.TotpEnabled)

	// 5. Delete MFA
	deleteReq := DisableMfaRequest{CurrentPassword: "password123"}
	body, _ = json.Marshal(deleteReq)
	rr = testutils.MockApiRequestWithAuth(t, string(body), "POST", "/account/api/mfa/delete", HandleDeleteMfa, token)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHandleVerifyTotp_InvalidCode(t *testing.T) {
	testutils.WithTestDB(t)
	token, _ := setupTestUserAndSession(t)

	verifyReq := TotpVerifyRequest{Code: "000000"}
	body, _ := json.Marshal(verifyReq)
	rr := testutils.MockApiRequestWithAuth(t, string(body), "POST", "/account/api/mfa/totp/verify", HandleVerifyTotp, token)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleVerifyTotp_DbError(t *testing.T) {
	testutils.WithTestDB(t)
	token, _ := setupTestUserAndSession(t)

	verifyReq := TotpVerifyRequest{Code: "123456"}
	body, _ := json.Marshal(verifyReq)
	
	// Close DB to trigger error
	db.CloseDB()

	rr := testutils.MockApiRequestWithAuth(t, string(body), "POST", "/account/api/mfa/totp/verify", HandleVerifyTotp, token)
	
	// GetUserFromRequest returns 401 if user lookup fails (e.g. DB closed)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestHandleDeleteMfa_DbError(t *testing.T) {
	testutils.WithTestDB(t)
	token, u := setupTestUserAndSession(t)

	// Set a valid hashed password
	hashed, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	_, _ = db.GetDB().Exec("UPDATE users SET password = ? WHERE id = ?", string(hashed), u.ID)

	deleteReq := DisableMfaRequest{CurrentPassword: "password123"}
	body, _ := json.Marshal(deleteReq)

	// Close DB to trigger error in DisableMfa
	db.CloseDB()

	rr := testutils.MockApiRequestWithAuth(t, string(body), "POST", "/account/api/mfa/delete", HandleDeleteMfa, token)
	
	// GetUserFromRequest returns 401 if user lookup fails
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}
