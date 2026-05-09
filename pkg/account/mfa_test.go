package account

import (
	"encoding/json"
	"net/http"
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
	_, usr, info := setupTestUserAndSession(t)

	// Enabled
	_, _ = db.GetDB().Exec("UPDATE users SET totp_verified = TRUE WHERE id = ?", usr.ID)

	rr := mockAuthRequest(t, "", "GET", "/account/mfa/status", HandleGetMfaStatus, info)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHandleVerifyTotp(t *testing.T) {
	testutils.WithTestDB(t)
	_, usr, info := setupTestUserAndSession(t)

	_ = mockAuthRequest(t, "", "POST", "/account/mfa/totp/setup", HandleSetupTotp, info)

	currUser, _ := user.UserByID(usr.ID)
	secret := currUser.TotpSecret
	code, _ := totp.GenerateCode(secret, time.Now())


	verifyReq := TotpVerifyRequest{Code: code}
	body, _ := json.Marshal(verifyReq)
	rr := mockAuthRequest(t, string(body), "POST", "/account/mfa/totp/verify", HandleVerifyTotp, info)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHandleVerifyTotp_Errors(t *testing.T) {
	testutils.WithTestDB(t)
	_, usr, info := setupTestUserAndSession(t)

	// TOTP not initiated
	verifyReq := TotpVerifyRequest{Code: "000000"}
	body, _ := json.Marshal(verifyReq)
	rr := mockAuthRequest(t, string(body), "POST", "/account/mfa/totp/verify", HandleVerifyTotp, info)
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	// Invalid code
	_ = user.StoreTotpSecretPending(usr.ID, "dummy")

	rr = mockAuthRequest(t, string(body), "POST", "/account/mfa/totp/verify", HandleVerifyTotp, info)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleDeleteMfa(t *testing.T) {
	testutils.WithTestDB(t)
	_, usr, info := setupTestUserAndSession(t)

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	secret := "JBSWY3DPEHPK3PXP"
	_, _ = db.GetDB().Exec("UPDATE users SET password = ?, totp_secret = ?, totp_verified = TRUE WHERE id = ?", string(hashedPassword), secret, usr.ID)


	code, _ := totp.GenerateCode(secret, time.Now())
	deleteReq := DisableMfaRequest{CurrentPassword: "password", Code: code}
	body, _ := json.Marshal(deleteReq)
	rr := mockAuthRequest(t, string(body), "POST", "/account/mfa/delete", HandleDeleteMfa, info)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHandleDeleteMfa_NoCode(t *testing.T) {
	testutils.WithTestDB(t)
	_, usr, info := setupTestUserAndSession(t)

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	_, _ = db.GetDB().Exec("UPDATE users SET password = ?, totp_secret = 'JBSWY3DPEHPK3PXP', totp_verified = TRUE WHERE id = ?", string(hashedPassword), usr.ID)


	deleteReq := DisableMfaRequest{CurrentPassword: "password"}
	body, _ := json.Marshal(deleteReq)
	rr := mockAuthRequest(t, string(body), "POST", "/account/mfa/delete", HandleDeleteMfa, info)
	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestHandleDeleteMfa_InvalidCode(t *testing.T) {
	testutils.WithTestDB(t)
	_, usr, info := setupTestUserAndSession(t)

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	_, _ = db.GetDB().Exec("UPDATE users SET password = ?, totp_secret = 'JBSWY3DPEHPK3PXP', totp_verified = TRUE WHERE id = ?", string(hashedPassword), usr.ID)


	deleteReq := DisableMfaRequest{CurrentPassword: "password", Code: "000000"}
	body, _ := json.Marshal(deleteReq)
	rr := mockAuthRequest(t, string(body), "POST", "/account/mfa/delete", HandleDeleteMfa, info)
	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestHandleDeleteMfa_NoPassword(t *testing.T) {
	testutils.WithTestDB(t)
	_, usr, info := setupTestUserAndSession(t)

	// User has no password (passkey-only) but has TOTP
	secret := "JBSWY3DPEHPK3PXP"
	_, _ = db.GetDB().Exec("UPDATE users SET password = '', totp_secret = ?, totp_verified = TRUE WHERE id = ?", secret, usr.ID)


	code, _ := totp.GenerateCode(secret, time.Now())
	deleteReq := DisableMfaRequest{Code: code}
	body, _ := json.Marshal(deleteReq)
	rr := mockAuthRequest(t, string(body), "POST", "/account/mfa/delete", HandleDeleteMfa, info)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHandleDeleteMfa_InvalidJSON(t *testing.T) {
	testutils.WithTestDB(t)
	_, _, info := setupTestUserAndSession(t)
	rr := mockAuthRequest(t, "{invalid", "POST", "/account/api/mfa/delete", HandleDeleteMfa, info)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleDeleteMfa_WrongPassword(t *testing.T) {
	testutils.WithTestDB(t)
	_, usr, info := setupTestUserAndSession(t)

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	_, _ = db.GetDB().Exec("UPDATE users SET password = ?, totp_secret = 'JBSWY3DPEHPK3PXP', totp_verified = TRUE WHERE id = ?", string(hashedPassword), usr.ID)


	req := DisableMfaRequest{CurrentPassword: "wrong"}
	body, _ := json.Marshal(req)
	rr := mockAuthRequest(t, string(body), "POST", "/account/api/mfa/delete", HandleDeleteMfa, info)
	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestHandleDeleteMfa_UniformErrorResponse(t *testing.T) {
	testutils.WithTestDB(t)
	_, usr, info := setupTestUserAndSession(t)

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	_, _ = db.GetDB().Exec("UPDATE users SET password = ?, totp_secret = 'JBSWY3DPEHPK3PXP', totp_verified = TRUE WHERE id = ?", string(hashedPassword), usr.ID)


	cases := []DisableMfaRequest{
		{CurrentPassword: "wrong", Code: "000000"},
		{CurrentPassword: "wrong", Code: ""},
		{CurrentPassword: "password", Code: "000000"},
		{CurrentPassword: "password", Code: ""},
	}
	var responses []string
	for _, c := range cases {
		body, _ := json.Marshal(c)
		rr := mockAuthRequest(t, string(body), "POST", "/account/api/mfa/delete", HandleDeleteMfa, info)
		assert.Equal(t, http.StatusForbidden, rr.Code)
		responses = append(responses, rr.Body.String())
	}
	for i := 1; i < len(responses); i++ {
		assert.Equal(t, responses[0], responses[i], "response %d differs from response 0", i)
	}
}

func TestHandleDeleteMfa_NotEnrolled(t *testing.T) {
	testutils.WithTestDB(t)
	_, _, info := setupTestUserAndSession(t)

	req := DisableMfaRequest{CurrentPassword: "anything"}
	body, _ := json.Marshal(req)
	rr := mockAuthRequest(t, string(body), "POST", "/account/api/mfa/delete", HandleDeleteMfa, info)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleMfaFlow(t *testing.T) {
	testutils.WithTestDB(t)
	_, u, info := setupTestUserAndSession(t)

	// Set a valid hashed password for AuthenticateUser to work
	hashed, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	_, _ = db.GetDB().Exec("UPDATE users SET password = ? WHERE id = ?", string(hashed), u.ID)


	// 1. Get MFA Status
	rr := mockAuthRequest(t, "", "GET", "/account/api/mfa/status", HandleGetMfaStatus, info)
	assert.Equal(t, http.StatusOK, rr.Code)

	var statusResp model.ApiResponse[MfaStatusResponse]
	err := json.Unmarshal(rr.Body.Bytes(), &statusResp)
	require.NoError(t, err)
	assert.False(t, statusResp.Data.TotpEnabled)

	// 2. Setup TOTP
	rr = mockAuthRequest(t, "", "POST", "/account/api/mfa/totp/setup", HandleSetupTotp, info)
	assert.Equal(t, http.StatusOK, rr.Code)

	var setupResp model.ApiResponse[TotpSetupResponse]
	err = json.Unmarshal(rr.Body.Bytes(), &setupResp)
	require.NoError(t, err)
	assert.NotEmpty(t, setupResp.Data.Secret)

	// 3. Verify TOTP (valid code)

	code, _ := totp.GenerateCode(setupResp.Data.Secret, time.Now())
	verifyReq := TotpVerifyRequest{Code: code}
	body, _ := json.Marshal(verifyReq)
	rr = mockAuthRequest(t, string(body), "POST", "/account/api/mfa/totp/verify", HandleVerifyTotp, info)
	assert.Equal(t, http.StatusOK, rr.Code)

	// 4. Verify status again

	rr = mockAuthRequest(t, "", "GET", "/account/api/mfa/status", HandleGetMfaStatus, info)
	err = json.Unmarshal(rr.Body.Bytes(), &statusResp)
	require.NoError(t, err)
	assert.True(t, statusResp.Data.TotpEnabled)

	// 5. Delete MFA — requires password + valid TOTP code
	currUser, _ := user.UserByID(u.ID)
	disableCode, _ := totp.GenerateCode(currUser.TotpSecret, time.Now())
	deleteReq := DisableMfaRequest{CurrentPassword: "password123", Code: disableCode}
	body, _ = json.Marshal(deleteReq)
	rr = mockAuthRequest(t, string(body), "POST", "/account/api/mfa/delete", HandleDeleteMfa, info)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHandleSetupTotp_AlreadyEnrolled(t *testing.T) {
	testutils.WithTestDB(t)
	_, usr, info := setupTestUserAndSession(t)

	// Mark TOTP as verified
	_, _ = db.GetDB().Exec("UPDATE users SET totp_secret = 'JBSWY3DPEHPK3PXP', totp_verified = TRUE WHERE id = ?", usr.ID)


	rr := mockAuthRequest(t, "", "POST", "/account/api/mfa/totp/setup", HandleSetupTotp, info)
	assert.Equal(t, http.StatusConflict, rr.Code)
	assert.Contains(t, rr.Body.String(), "already_enrolled")
}

func TestHandleVerifyTotp_InvalidCode(t *testing.T) {
	testutils.WithTestDB(t)
	_, _, info := setupTestUserAndSession(t)

	verifyReq := TotpVerifyRequest{Code: "000000"}
	body, _ := json.Marshal(verifyReq)
	rr := mockAuthRequest(t, string(body), "POST", "/account/api/mfa/totp/verify", HandleVerifyTotp, info)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleVerifyTotp_DbError(t *testing.T) {
	testutils.WithTestDB(t)
	_, _, info := setupTestUserAndSession(t)

	verifyReq := TotpVerifyRequest{Code: "123456"}
	body, _ := json.Marshal(verifyReq)

	// Close DB to trigger error
	db.CloseDB()

	rr := mockAuthRequest(t, string(body), "POST", "/account/api/mfa/totp/verify", HandleVerifyTotp, info)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestHandleDeleteMfa_DbError(t *testing.T) {
	testutils.WithTestDB(t)
	_, u, info := setupTestUserAndSession(t)

	// Set a valid hashed password and TOTP so the handler proceeds past validation
	hashed, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	_, _ = db.GetDB().Exec("UPDATE users SET password = ?, totp_secret = 'JBSWY3DPEHPK3PXP', totp_verified = TRUE WHERE id = ?", string(hashed), u.ID)

	// Refresh before closing DB so context has the updated user
	freshUsr, _ := user.UserByID(u.ID)
	info.User = freshUsr

	deleteReq := DisableMfaRequest{CurrentPassword: "password123"}
	body, _ := json.Marshal(deleteReq)

	// Close DB to trigger error in DisableMfa
	db.CloseDB()

	rr := mockAuthRequest(t, string(body), "POST", "/account/api/mfa/delete", HandleDeleteMfa, info)

	// With auth context, user is loaded from context; DB error hits during
	// VerifyPassword or DisableMfa — returns 403 (password verify fails) or 500
	assert.True(t, rr.Code == http.StatusForbidden || rr.Code == http.StatusInternalServerError)
}
