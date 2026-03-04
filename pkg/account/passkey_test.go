package account

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/model"
	"github.com/eugenioenko/autentico/pkg/passkey"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"strings"
)

func TestHandleListPasskeys(t *testing.T) {
	testutils.WithTestDB(t)
	token, usr := setupTestUserAndSession(t)

	_ = passkey.CreatePasskeyCredential(passkey.PasskeyCredential{
		ID:         "pk1",
		UserID:     usr.ID,
		Name:       "My Passkey",
		Credential: "{}",
	})

	rr := testutils.MockApiRequestWithAuth(t, "", "GET", "/account/api/passkeys", HandleListPasskeys, token)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHandleDeletePasskey(t *testing.T) {
	testutils.WithTestDB(t)
	token, usr := setupTestUserAndSession(t)

	_ = passkey.CreatePasskeyCredential(passkey.PasskeyCredential{
		ID:         "pk1",
		UserID:     usr.ID,
		Name:       "My Passkey",
		Credential: "{}",
	})

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /account/api/passkeys/{id}", HandleDeletePasskey)

	req := httptest.NewRequest("DELETE", "/account/api/passkeys/pk1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	// Not owned
	req = httptest.NewRequest("DELETE", "/account/api/passkeys/otherpk", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestHandleRenamePasskey(t *testing.T) {
	testutils.WithTestDB(t)
	token, usr := setupTestUserAndSession(t)

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
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	// Not owned
	req = httptest.NewRequest("PUT", "/account/api/passkeys/otherpk", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestHandleAddPasskeyBegin(t *testing.T) {
	testutils.WithTestDB(t)
	token, _ := setupTestUserAndSession(t)
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AppDomain = "localhost"
		config.Bootstrap.AppURL = "http://localhost"
		config.Values.PasskeyRPName = "Test"
	})

	rr := testutils.MockApiRequestWithAuth(t, "", "POST", "/account/api/passkeys/add/begin", HandleAddPasskeyBegin, token)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHandleAddPasskeyFinish_Errors(t *testing.T) {
	testutils.WithTestDB(t)
	token, _ := setupTestUserAndSession(t)

	// Missing challenge_id
	req := httptest.NewRequest("POST", "/account/api/passkeys/add/finish?challenge_id=invalid", nil)
	req.Header.Set("Authorization", "Bearer "+token)
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
	req.Header.Set("Authorization", "Bearer "+token)
	rr = httptest.NewRecorder()
	HandleAddPasskeyFinish(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestHandleAddPasskeyFinish_InvalidChallengeData(t *testing.T) {
	testutils.WithTestDB(t)
	token, usr := setupTestUserAndSession(t)

	challenge := passkey.PasskeyChallenge{
		ID:            "chall1",
		UserID:        usr.ID,
		Type:          "account-registration",
		ExpiresAt:     time.Now().Add(time.Hour),
		ChallengeData: "{invalid",
	}
	_ = passkey.CreatePasskeyChallenge(challenge)

	req := httptest.NewRequest("POST", "/account/api/passkeys/add/finish?challenge_id=chall1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	HandleAddPasskeyFinish(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestHandleRenamePasskey_InvalidJSON(t *testing.T) {
	testutils.WithTestDB(t)
	token, _ := setupTestUserAndSession(t)
	
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /account/api/passkeys/{id}", HandleRenamePasskey)
	
	req := httptest.NewRequest("PUT", "/account/api/passkeys/pk1", nil) // No body
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleAddPasskeyFinish_MissingChallengeID(t *testing.T) {
	testutils.WithTestDB(t)
	token, _ := setupTestUserAndSession(t)

	req := httptest.NewRequest("POST", "/account/api/passkeys/add/finish", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	HandleAddPasskeyFinish(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Missing challenge_id")
}

func TestHandleAddPasskeyBegin_Success(t *testing.T) {
	testutils.WithTestDB(t)
	token, _ := setupTestUserAndSession(t)

	req := httptest.NewRequest("POST", "/account/api/passkeys/add/begin", nil)
	req.Header.Set("Authorization", "Bearer "+token)
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
	token, _ := setupTestUserAndSession(t)

	// No challenge created in DB
	req := httptest.NewRequest("POST", "/account/api/passkeys/add/finish?challenge_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	HandleAddPasskeyFinish(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid challenge")
}

func TestHandleAddPasskeyFinish_ChallengeExpired(t *testing.T) {
	testutils.WithTestDB(t)
	token, u := setupTestUserAndSession(t)

	// Create an expired challenge with CORRECT type: account-registration
	_, _ = db.GetDB().Exec(`
		INSERT INTO passkey_challenges (id, user_id, challenge_data, type, created_at, expires_at)
		VALUES ('expired', ?, '{}', 'account-registration', datetime('now', '-2 hour'), datetime('now', '-1 hour'))
	`, u.ID)

	req := httptest.NewRequest("POST", "/account/api/passkeys/add/finish?challenge_id=expired", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	HandleAddPasskeyFinish(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Challenge expired")
}

func TestHandleAddPasskeyFinish_InvalidBody(t *testing.T) {
	testutils.WithTestDB(t)
	token, u := setupTestUserAndSession(t)

	// Create a valid challenge
	_, _ = db.GetDB().Exec(`
		INSERT INTO passkey_challenges (id, user_id, challenge_data, type, created_at, expires_at)
		VALUES ('valid', ?, '{}', 'account-registration', datetime('now'), datetime('now', '+5 minute'))
	`, u.ID)

	req := httptest.NewRequest("POST", "/account/api/passkeys/add/finish?challenge_id=valid", strings.NewReader("{invalid"))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	HandleAddPasskeyFinish(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleAddPasskeyFinish_WrongUser(t *testing.T) {
	testutils.WithTestDB(t)
	token, _ := setupTestUserAndSession(t) // token for u1

	// Create a challenge for OTHER user
	testutils.InsertTestUser(t, "other")
	_, _ = db.GetDB().Exec(`
		INSERT INTO passkey_challenges (id, user_id, challenge_data, type, created_at, expires_at)
		VALUES ('other-chall', 'other', '{}', 'account-registration', datetime('now'), datetime('now', '+5 minute'))
	`)

	req := httptest.NewRequest("POST", "/account/api/passkeys/add/finish?challenge_id=other-chall", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	HandleAddPasskeyFinish(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "Challenge does not belong to you")
}

func TestHandleRenamePasskey_Success_Extra(t *testing.T) {
	testutils.WithTestDB(t)
	token, u := setupTestUserAndSession(t)

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
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	
	// Verify renamed
	var name string
	_ = db.GetDB().QueryRow("SELECT name FROM passkey_credentials WHERE id = 'pk1'").Scan(&name)
	assert.Equal(t, "New Name", name)
}

func TestHandleDeletePasskey_Extra(t *testing.T) {
	testutils.WithTestDB(t)
	token, _ := setupTestUserAndSession(t)

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /account/api/passkeys/{id}", HandleDeletePasskey)

	req := httptest.NewRequest("DELETE", "/account/api/passkeys/none", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
}
