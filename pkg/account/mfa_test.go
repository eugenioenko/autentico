package account

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/mfa"
	"github.com/eugenioenko/autentico/pkg/model"
	"github.com/eugenioenko/autentico/pkg/user"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestHandleDeleteMfaSharesAccountBudget(t *testing.T) {
	testutils.WithTestDB(t)
	_, usr, info := setupTestUserAndSession(t)
	hash, err := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.MinCost)
	require.NoError(t, err)
	const secret = "JBSWY3DPEHPK3PXP"
	_, err = db.GetDB().Exec(`UPDATE users SET password=?, totp_secret=?, totp_verified=TRUE WHERE id=?`, string(hash), secret, usr.ID)
	require.NoError(t, err)
	send := func(password, code string) (int, string) {
		body, marshalErr := json.Marshal(DisableMfaRequest{CurrentPassword: password, Code: code})
		require.NoError(t, marshalErr)
		rr := mockAuthRequest(t, string(body), http.MethodDelete, "/account/api/mfa/totp", HandleDeleteMfa, info)
		return rr.Code, rr.Body.String()
	}
	// Malformed codes are invalid in every timestep, without a numeric-code collision.
	for range 4 {
		status, _ := send("password123", "invalid")
		require.Equal(t, http.StatusForbidden, status)
	}
	valid, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	status, body := send("wrong-password", valid)
	require.Equal(t, http.StatusForbidden, status)
	require.Contains(t, body, "invalid_credentials")
	var attempts int
	require.NoError(t, db.GetDB().QueryRow(`SELECT totp_failed_attempts FROM users WHERE id=?`, usr.ID).Scan(&attempts))
	require.Equal(t, 4, attempts, "password failure must neither verify nor count a TOTP guess")
	// A failure at another entry point uses the same remaining attempt.
	require.ErrorIs(t, mfa.VerifyPasswordGrantTotp(usr.ID, "invalid"), mfa.ErrTotpLocked)
	status, body = send("password123", valid)
	require.Equal(t, http.StatusForbidden, status)
	require.Contains(t, body, "mfa_locked")
	current, err := user.UserByID(usr.ID)
	require.NoError(t, err)
	require.True(t, current.TotpVerified)
	_, err = db.GetDB().Exec(`UPDATE users SET totp_locked_until=? WHERE id=?`, time.Now().Add(-time.Second), usr.ID)
	require.NoError(t, err)
	status, body = send("password123", valid)
	require.Equal(t, http.StatusOK, status, body)
	current, err = user.UserByID(usr.ID)
	require.NoError(t, err)
	require.False(t, current.TotpVerified)
}

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

	hashedPw, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	_, _ = db.GetDB().Exec("UPDATE users SET password = ? WHERE id = ?", string(hashedPw), usr.ID)

	setupReq := PasswordConfirmRequest{CurrentPassword: "password"}
	setupBody, _ := json.Marshal(setupReq)
	_ = mockAuthRequest(t, string(setupBody), "POST", "/account/mfa/totp/setup", HandleSetupTotp, info)

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
	_, _ = db.GetDB().Exec("UPDATE users SET password = ? WHERE id = ?", string(hashedPassword), usr.ID)
	require.NoError(t, user.SaveTotpSecret(usr.ID, secret))

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
	_, _ = db.GetDB().Exec("UPDATE users SET password = ? WHERE id = ?", string(hashedPassword), usr.ID)
	require.NoError(t, user.SaveTotpSecret(usr.ID, "JBSWY3DPEHPK3PXP"))

	deleteReq := DisableMfaRequest{CurrentPassword: "password"}
	body, _ := json.Marshal(deleteReq)
	rr := mockAuthRequest(t, string(body), "POST", "/account/mfa/delete", HandleDeleteMfa, info)
	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestHandleDeleteMfa_InvalidCode(t *testing.T) {
	testutils.WithTestDB(t)
	_, usr, info := setupTestUserAndSession(t)

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	_, _ = db.GetDB().Exec("UPDATE users SET password = ? WHERE id = ?", string(hashedPassword), usr.ID)
	require.NoError(t, user.SaveTotpSecret(usr.ID, "JBSWY3DPEHPK3PXP"))

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
	_, _ = db.GetDB().Exec("UPDATE users SET password = '' WHERE id = ?", usr.ID)
	require.NoError(t, user.SaveTotpSecret(usr.ID, secret))

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
	_, _ = db.GetDB().Exec("UPDATE users SET password = ? WHERE id = ?", string(hashedPassword), usr.ID)
	require.NoError(t, user.SaveTotpSecret(usr.ID, "JBSWY3DPEHPK3PXP"))

	req := DisableMfaRequest{CurrentPassword: "wrong"}
	body, _ := json.Marshal(req)
	rr := mockAuthRequest(t, string(body), "POST", "/account/api/mfa/delete", HandleDeleteMfa, info)
	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestHandleDeleteMfa_UniformErrorResponse(t *testing.T) {
	testutils.WithTestDB(t)
	_, usr, info := setupTestUserAndSession(t)

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	_, _ = db.GetDB().Exec("UPDATE users SET password = ? WHERE id = ?", string(hashedPassword), usr.ID)
	require.NoError(t, user.SaveTotpSecret(usr.ID, "JBSWY3DPEHPK3PXP"))

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
	setupReq := PasswordConfirmRequest{CurrentPassword: "password123"}
	setupBody, _ := json.Marshal(setupReq)
	rr = mockAuthRequest(t, string(setupBody), "POST", "/account/api/mfa/totp/setup", HandleSetupTotp, info)
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
	// A new authenticator timestep is required after enrollment confirmation.
	disableCode, _ := totp.GenerateCode(currUser.TotpSecret, time.Now().Add(30*time.Second))
	deleteReq := DisableMfaRequest{CurrentPassword: "password123", Code: disableCode}
	body, _ = json.Marshal(deleteReq)
	rr = mockAuthRequest(t, string(body), "POST", "/account/api/mfa/delete", HandleDeleteMfa, info)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHandleDeleteMfaReplayWriteFailureAndPasswordFailure(t *testing.T) {
	testutils.WithTestDB(t)
	_, usr, info := setupTestUserAndSession(t)
	hash, err := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	require.NoError(t, err)
	const secret = "JBSWY3DPEHPK3PXP"
	_, err = db.GetDB().Exec(`UPDATE users SET password=? WHERE id=?`, string(hash), usr.ID)
	require.NoError(t, user.SaveTotpSecret(usr.ID, secret))
	require.NoError(t, err)
	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	send := func(password string) int {
		body, marshalErr := json.Marshal(DisableMfaRequest{CurrentPassword: password, Code: code})
		require.NoError(t, marshalErr)
		return mockAuthRequest(t, string(body), http.MethodDelete, "/account/api/mfa/totp", HandleDeleteMfa, info).Code
	}
	require.Equal(t, http.StatusForbidden, send("wrong-password"))
	_, err = db.GetDB().Exec(`CREATE TRIGGER fail_replay BEFORE UPDATE OF totp_last_used_step ON users BEGIN SELECT RAISE(FAIL,'injected replay failure'); END`)
	require.NoError(t, err)
	require.Equal(t, http.StatusInternalServerError, send("password123"))
	current, err := user.UserByID(usr.ID)
	require.NoError(t, err)
	require.True(t, current.TotpVerified)
	_, err = db.GetDB().Exec("DROP TRIGGER fail_replay")
	require.NoError(t, err)
	// Neither a wrong password nor a failed persistence attempt consumed the code.
	require.Equal(t, http.StatusOK, send("password123"))
}

func TestHandleSetupTotp_RequiresPassword(t *testing.T) {
	testutils.WithTestDB(t)
	_, usr, info := setupTestUserAndSession(t)

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	_, _ = db.GetDB().Exec("UPDATE users SET password = ? WHERE id = ?", string(hashedPassword), usr.ID)

	// Without password — should fail
	req := PasswordConfirmRequest{}
	body, _ := json.Marshal(req)
	rr := mockAuthRequest(t, string(body), "POST", "/account/api/mfa/totp/setup", HandleSetupTotp, info)
	assert.Equal(t, http.StatusForbidden, rr.Code)

	// Wrong password — should fail
	req = PasswordConfirmRequest{CurrentPassword: "wrong"}
	body, _ = json.Marshal(req)
	rr = mockAuthRequest(t, string(body), "POST", "/account/api/mfa/totp/setup", HandleSetupTotp, info)
	assert.Equal(t, http.StatusForbidden, rr.Code)

	// Correct password — should succeed
	req = PasswordConfirmRequest{CurrentPassword: "password"}
	body, _ = json.Marshal(req)
	rr = mockAuthRequest(t, string(body), "POST", "/account/api/mfa/totp/setup", HandleSetupTotp, info)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHandleSetupTotp_PasskeyUserSkipsPassword(t *testing.T) {
	testutils.WithTestDB(t)
	_, usr, info := setupTestUserAndSession(t)

	_, _ = db.GetDB().Exec("UPDATE users SET password = '' WHERE id = ?", usr.ID)

	req := PasswordConfirmRequest{}
	body, _ := json.Marshal(req)
	rr := mockAuthRequest(t, string(body), "POST", "/account/api/mfa/totp/setup", HandleSetupTotp, info)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHandleSetupTotp_InvalidJSON(t *testing.T) {
	testutils.WithTestDB(t)
	_, _, info := setupTestUserAndSession(t)

	rr := mockAuthRequest(t, "{invalid", "POST", "/account/api/mfa/totp/setup", HandleSetupTotp, info)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleSetupTotp_AlreadyEnrolled(t *testing.T) {
	testutils.WithTestDB(t)
	_, usr, info := setupTestUserAndSession(t)

	// Set password and mark TOTP as verified
	hashedPw, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	_, _ = db.GetDB().Exec("UPDATE users SET password = ? WHERE id = ?", string(hashedPw), usr.ID)
	require.NoError(t, user.SaveTotpSecret(usr.ID, "JBSWY3DPEHPK3PXP"))

	setupReq := PasswordConfirmRequest{CurrentPassword: "password"}
	body, _ := json.Marshal(setupReq)
	rr := mockAuthRequest(t, string(body), "POST", "/account/api/mfa/totp/setup", HandleSetupTotp, info)
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
	_, _ = db.GetDB().Exec("UPDATE users SET password = ? WHERE id = ?", string(hashed), u.ID)
	require.NoError(t, user.SaveTotpSecret(u.ID, "JBSWY3DPEHPK3PXP"))

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
