package account

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/middleware"
	"github.com/eugenioenko/autentico/pkg/model"
	"github.com/eugenioenko/autentico/pkg/passkey"
	"github.com/eugenioenko/autentico/pkg/user"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestHandleListPasskeys(t *testing.T) {
	testutils.WithTestDB(t)
	_, usr, info := setupTestUserAndSession(t)

	_ = passkey.CreatePasskeyCredential(passkey.PasskeyCredential{
		ID:         "pk1",
		UserID:     usr.ID,
		Name:       "My Passkey",
		Credential: "{}",
	})

	rr := mockAuthRequest(t, "", "GET", "/account/api/passkeys", HandleListPasskeys, info)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHandleDeletePasskey(t *testing.T) {
	testutils.WithTestDB(t)
	_, usr, info := setupTestUserAndSession(t)

	// Clear password (passkey-only user) and refresh info
	_, _ = db.GetDB().Exec("UPDATE users SET password = '' WHERE id = ?", usr.ID)
	refreshed, _ := user.UserByID(usr.ID)
	info.User = refreshed

	_ = passkey.CreatePasskeyCredential(passkey.PasskeyCredential{
		ID:         "pk1",
		UserID:     usr.ID,
		Name:       "My Passkey",
		Credential: "{}",
	})

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /account/api/passkeys/{id}", HandleDeletePasskey)

	// Passkey user (no password) — should succeed
	deleteReq := PasswordConfirmRequest{}
	body, _ := json.Marshal(deleteReq)
	req := httptest.NewRequest("DELETE", "/account/api/passkeys/pk1", bytes.NewBuffer(body))
	req = middleware.WithAuthInfo(req, info)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	// Not owned
	body, _ = json.Marshal(deleteReq)
	req = httptest.NewRequest("DELETE", "/account/api/passkeys/otherpk", bytes.NewBuffer(body))
	req = middleware.WithAuthInfo(req, info)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestHandleRenamePasskey(t *testing.T) {
	testutils.WithTestDB(t)
	_, usr, info := setupTestUserAndSession(t)

	_ = passkey.CreatePasskeyCredential(passkey.PasskeyCredential{
		ID:         "pk1",
		UserID:     usr.ID,
		Name:       "Old Name",
		Credential: "{}",
	})

	mux := http.NewServeMux()
	mux.HandleFunc("PUT /account/api/passkeys/{id}", HandleRenamePasskey)

	renameReq := PasskeyRenameRequest{Name: "New Name"}
	body, _ := json.Marshal(renameReq)
	req := httptest.NewRequest("PUT", "/account/api/passkeys/pk1", bytes.NewBuffer(body))
	req = middleware.WithAuthInfo(req, info)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	// Not owned
	req = httptest.NewRequest("PUT", "/account/api/passkeys/otherpk", bytes.NewBuffer(body))
	req = middleware.WithAuthInfo(req, info)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestHandleAddPasskeyBegin(t *testing.T) {
	testutils.WithTestDB(t)
	_, usr, info := setupTestUserAndSession(t)

	// Clear password (passkey-only user)
	_, _ = db.GetDB().Exec("UPDATE users SET password = '' WHERE id = ?", usr.ID)

	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AppDomain = "localhost"
		config.Bootstrap.AppURL = "http://localhost"
		config.Values.PasskeyRPName = "Test"
	})

	req := PasswordConfirmRequest{}
	body, _ := json.Marshal(req)
	rr := mockAuthRequest(t, string(body), "POST", "/account/api/passkeys/add/begin", HandleAddPasskeyBegin, info)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHandleAddPasskeyFinish_Errors(t *testing.T) {
	testutils.WithTestDB(t)
	_, _, info := setupTestUserAndSession(t)

	// Missing challenge_id
	req := httptest.NewRequest("POST", "/account/api/passkeys/add/finish?challenge_id=invalid", nil)
	req = middleware.WithAuthInfo(req, info)
	rr := httptest.NewRecorder()
	HandleAddPasskeyFinish(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	// Wrong user
	testutils.InsertTestUser(t, "other")
	challenge := passkey.PasskeyChallenge{
		ID:            "chall1",
		UserID:        "other",
		Type:          "account-registration",
		ExpiresAt:     time.Now().Add(time.Hour),
		ChallengeData: "{}",
	}
	_ = passkey.CreatePasskeyChallenge(challenge)
	req = httptest.NewRequest("POST", "/account/api/passkeys/add/finish?challenge_id=chall1", nil)
	req = middleware.WithAuthInfo(req, info)
	rr = httptest.NewRecorder()
	HandleAddPasskeyFinish(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestHandleAddPasskeyFinish_InvalidChallengeData(t *testing.T) {
	testutils.WithTestDB(t)
	_, usr, info := setupTestUserAndSession(t)

	challenge := passkey.PasskeyChallenge{
		ID:            "chall1",
		UserID:        usr.ID,
		Type:          "account-registration",
		ExpiresAt:     time.Now().Add(time.Hour),
		ChallengeData: "{invalid",
	}
	_ = passkey.CreatePasskeyChallenge(challenge)

	req := httptest.NewRequest("POST", "/account/api/passkeys/add/finish?challenge_id=chall1", nil)
	req = middleware.WithAuthInfo(req, info)
	rr := httptest.NewRecorder()
	HandleAddPasskeyFinish(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestHandleRenamePasskey_InvalidJSON(t *testing.T) {
	testutils.WithTestDB(t)
	_, _, info := setupTestUserAndSession(t)

	mux := http.NewServeMux()
	mux.HandleFunc("PUT /account/api/passkeys/{id}", HandleRenamePasskey)

	req := httptest.NewRequest("PUT", "/account/api/passkeys/pk1", nil) // No body
	req = middleware.WithAuthInfo(req, info)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleAddPasskeyFinish_MissingChallengeID(t *testing.T) {
	testutils.WithTestDB(t)
	_, _, info := setupTestUserAndSession(t)

	req := httptest.NewRequest("POST", "/account/api/passkeys/add/finish", nil)
	req = middleware.WithAuthInfo(req, info)
	rr := httptest.NewRecorder()
	HandleAddPasskeyFinish(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Missing challenge_id")
}

func TestHandleAddPasskeyBegin_Success(t *testing.T) {
	testutils.WithTestDB(t)
	_, usr, info := setupTestUserAndSession(t)

	// Clear password (passkey-only user) and refresh info
	_, _ = db.GetDB().Exec("UPDATE users SET password = '' WHERE id = ?", usr.ID)
	refreshed, _ := user.UserByID(usr.ID)
	info.User = refreshed

	confirmReq := PasswordConfirmRequest{}
	body, _ := json.Marshal(confirmReq)
	req := httptest.NewRequest("POST", "/account/api/passkeys/add/begin", bytes.NewBuffer(body))
	req = middleware.WithAuthInfo(req, info)
	rr := httptest.NewRecorder()
	HandleAddPasskeyBegin(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp model.ApiResponse[map[string]any]
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.NotEmpty(t, resp.Data["challenge_id"])
	assert.NotNil(t, resp.Data["options"])
}

func TestHandleAddPasskeyFinish_InvalidChallenge(t *testing.T) {
	testutils.WithTestDB(t)
	_, _, info := setupTestUserAndSession(t)

	// No challenge created in DB
	req := httptest.NewRequest("POST", "/account/api/passkeys/add/finish?challenge_id=nonexistent", nil)
	req = middleware.WithAuthInfo(req, info)
	rr := httptest.NewRecorder()
	HandleAddPasskeyFinish(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid challenge")
}

func TestHandleAddPasskeyFinish_ChallengeExpired(t *testing.T) {
	testutils.WithTestDB(t)
	_, u, info := setupTestUserAndSession(t)

	// Create an expired challenge with CORRECT type: account-registration
	_, _ = db.GetDB().Exec(`
		INSERT INTO passkey_challenges (id, user_id, challenge_data, type, created_at, expires_at)
		VALUES ('expired', ?, '{}', 'account-registration', datetime('now', '-2 hour'), datetime('now', '-1 hour'))
	`, u.ID)

	req := httptest.NewRequest("POST", "/account/api/passkeys/add/finish?challenge_id=expired", nil)
	req = middleware.WithAuthInfo(req, info)
	rr := httptest.NewRecorder()
	HandleAddPasskeyFinish(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Challenge expired")
}

func TestHandleAddPasskeyFinish_InvalidBody(t *testing.T) {
	testutils.WithTestDB(t)
	_, u, info := setupTestUserAndSession(t)

	// Create a valid challenge
	_, _ = db.GetDB().Exec(`
		INSERT INTO passkey_challenges (id, user_id, challenge_data, type, created_at, expires_at)
		VALUES ('valid', ?, '{}', 'account-registration', datetime('now'), datetime('now', '+5 minute'))
	`, u.ID)

	req := httptest.NewRequest("POST", "/account/api/passkeys/add/finish?challenge_id=valid", strings.NewReader("{invalid"))
	req = middleware.WithAuthInfo(req, info)
	rr := httptest.NewRecorder()
	HandleAddPasskeyFinish(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleAddPasskeyFinish_WrongUser(t *testing.T) {
	testutils.WithTestDB(t)
	_, _, info := setupTestUserAndSession(t) // info for u1

	// Create a challenge for OTHER user
	testutils.InsertTestUser(t, "other")
	_, _ = db.GetDB().Exec(`
		INSERT INTO passkey_challenges (id, user_id, challenge_data, type, created_at, expires_at)
		VALUES ('other-chall', 'other', '{}', 'account-registration', datetime('now'), datetime('now', '+5 minute'))
	`)

	req := httptest.NewRequest("POST", "/account/api/passkeys/add/finish?challenge_id=other-chall", nil)
	req = middleware.WithAuthInfo(req, info)
	rr := httptest.NewRecorder()
	HandleAddPasskeyFinish(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "Challenge does not belong to you")
}

func TestHandleRenamePasskey_Success_Extra(t *testing.T) {
	testutils.WithTestDB(t)
	_, u, info := setupTestUserAndSession(t)

	// Create a passkey in the CORRECT table: passkey_credentials
	_, _ = db.GetDB().Exec(`
		INSERT INTO passkey_credentials (id, user_id, name, credential, created_at)
		VALUES ('pk1', ?, 'Old Name', '{}', CURRENT_TIMESTAMP)
	`, u.ID)

	mux := http.NewServeMux()
	mux.HandleFunc("PATCH /account/api/passkeys/{id}", HandleRenamePasskey)

	renameReq := PasskeyRenameRequest{Name: "New Name"}
	body, _ := json.Marshal(renameReq)
	req := httptest.NewRequest("PATCH", "/account/api/passkeys/pk1", bytes.NewBuffer(body))
	req = middleware.WithAuthInfo(req, info)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	// Verify renamed
	var name string
	_ = db.GetDB().QueryRow("SELECT name FROM passkey_credentials WHERE id = 'pk1'").Scan(&name)
	assert.Equal(t, "New Name", name)
}

func TestHandleAddPasskeyBegin_RequiresPassword(t *testing.T) {
	testutils.WithTestDB(t)
	_, usr, info := setupTestUserAndSession(t)

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	_, _ = db.GetDB().Exec("UPDATE users SET password = ? WHERE id = ?", string(hashedPassword), usr.ID)

	// Wrong password — should fail
	req := PasswordConfirmRequest{CurrentPassword: "wrong"}
	body, _ := json.Marshal(req)
	rr := mockAuthRequest(t, string(body), "POST", "/account/api/passkeys/add/begin", HandleAddPasskeyBegin, info)
	assert.Equal(t, http.StatusForbidden, rr.Code)

	// Correct password — should succeed
	req = PasswordConfirmRequest{CurrentPassword: "password"}
	body, _ = json.Marshal(req)
	rr = mockAuthRequest(t, string(body), "POST", "/account/api/passkeys/add/begin", HandleAddPasskeyBegin, info)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHandleDeletePasskey_RequiresPassword(t *testing.T) {
	testutils.WithTestDB(t)
	_, usr, info := setupTestUserAndSession(t)

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	_, _ = db.GetDB().Exec("UPDATE users SET password = ? WHERE id = ?", string(hashedPassword), usr.ID)

	_ = passkey.CreatePasskeyCredential(passkey.PasskeyCredential{
		ID:         "pk-pwd",
		UserID:     usr.ID,
		Name:       "Test",
		Credential: "{}",
	})

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /account/api/passkeys/{id}", HandleDeletePasskey)

	// Wrong password — should fail
	deleteReq := PasswordConfirmRequest{CurrentPassword: "wrong"}
	body, _ := json.Marshal(deleteReq)
	req := httptest.NewRequest("DELETE", "/account/api/passkeys/pk-pwd", bytes.NewBuffer(body))
	req = middleware.WithAuthInfo(req, info)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)

	// Correct password — should succeed
	deleteReq = PasswordConfirmRequest{CurrentPassword: "password"}
	body, _ = json.Marshal(deleteReq)
	req = httptest.NewRequest("DELETE", "/account/api/passkeys/pk-pwd", bytes.NewBuffer(body))
	req = middleware.WithAuthInfo(req, info)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHandleAddPasskeyBegin_InvalidJSON(t *testing.T) {
	testutils.WithTestDB(t)
	_, _, info := setupTestUserAndSession(t)

	rr := mockAuthRequest(t, "{invalid", "POST", "/account/api/passkeys/add/begin", HandleAddPasskeyBegin, info)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleDeletePasskey_InvalidJSON(t *testing.T) {
	testutils.WithTestDB(t)
	_, _, info := setupTestUserAndSession(t)

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /account/api/passkeys/{id}", HandleDeletePasskey)

	req := httptest.NewRequest("DELETE", "/account/api/passkeys/pk1", nil)
	req = middleware.WithAuthInfo(req, info)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleDeletePasskey_Extra(t *testing.T) {
	testutils.WithTestDB(t)
	_, _, info := setupTestUserAndSession(t)

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /account/api/passkeys/{id}", HandleDeletePasskey)

	deleteReq := PasswordConfirmRequest{}
	body, _ := json.Marshal(deleteReq)
	req := httptest.NewRequest("DELETE", "/account/api/passkeys/none", bytes.NewBuffer(body))
	req = middleware.WithAuthInfo(req, info)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
}
