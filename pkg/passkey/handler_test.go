package passkey

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupPasskeyTestUser inserts a minimal user row and returns (id, username).
func setupPasskeyTestUser(t *testing.T) (id, username string) {
	t.Helper()
	id = "passkey-handler-test-user"
	username = "passkeytest@example.com"
	_, err := db.GetDB().Exec(
		`INSERT INTO users (id, username, email, password, role) VALUES (?, ?, ?, ?, ?)`,
		id, username, username, "hashed", "user",
	)
	require.NoError(t, err)
	return
}

// withPasskeyConfig sets the standard config needed for WebAuthn ceremony handlers.
func withPasskeyConfig(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AppDomain = "localhost"
		config.Bootstrap.AppURL = "http://localhost:9999"
		config.Values.PasskeyRPName = "Test"
	})
}

// --- HandleLoginBegin ---

func TestHandleLoginBegin_MissingUsername(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/passkey/login/begin", nil)
	rr := httptest.NewRecorder()
	HandleLoginBegin(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	var resp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Contains(t, resp["error"], "missing username")
}

func TestHandleLoginBegin_UnknownUser(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/passkey/login/begin?username=nobody@example.com", nil)
	rr := httptest.NewRecorder()
	HandleLoginBegin(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	var resp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	// Generic error — must not reveal whether the user exists
	assert.NotEmpty(t, resp["error"])
}

func TestHandleLoginBegin_NoCreds_PasswordMode(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() { config.Values.AuthMode = "password" })

	_, username := setupPasskeyTestUser(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/passkey/login/begin?username="+username, nil)
	rr := httptest.NewRecorder()
	HandleLoginBegin(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	var resp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Contains(t, resp["error"], "no passkeys registered")
}

func TestHandleLoginBegin_NoCreds_PasswordAndPasskeyMode(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() { config.Values.AuthMode = "password_and_passkey" })

	_, username := setupPasskeyTestUser(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/passkey/login/begin?username="+username, nil)
	rr := httptest.NewRecorder()
	HandleLoginBegin(rr, req)

	// User has no passkeys and mode is password_and_passkey → should fall back to password
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	var resp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Contains(t, resp["error"], "no passkeys registered")
}

func TestHandleLoginBegin_NoCreds_PasskeyOnlyMode(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() { config.Values.AuthMode = "passkey_only" })

	_, username := setupPasskeyTestUser(t)

	req := httptest.NewRequest(http.MethodGet,
		"/oauth2/passkey/login/begin?username="+username+"&redirect_uri=http://localhost/cb&state=st1&client_id=c1&scope=openid",
		nil)
	rr := httptest.NewRecorder()
	HandleLoginBegin(rr, req)

	// Passkey registration is only allowed during signup, not login.
	// A user with no passkeys must always get an error, regardless of auth mode.
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	var resp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Contains(t, resp["error"], "no passkeys registered")
}

func TestHandleLoginBegin_WithCreds(t *testing.T) {
	testutils.WithTestDB(t)
	withPasskeyConfig(t)
	testutils.WithConfigOverride(t, func() { config.Values.AuthMode = "password_and_passkey" })

	userID, username := setupPasskeyTestUser(t)
	require.NoError(t, CreatePasskeyCredential(PasskeyCredential{
		ID:         "existing-cred-begin",
		UserID:     userID,
		Credential: sampleCredentialJSON(),
	}))

	req := httptest.NewRequest(http.MethodGet,
		"/oauth2/passkey/login/begin?username="+username+"&redirect_uri=http://localhost/cb&state=st1&client_id=c1&scope=openid",
		nil)
	rr := httptest.NewRecorder()
	HandleLoginBegin(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, "authentication", resp["type"])
	assert.NotEmpty(t, resp["challenge_id"])
	assert.NotNil(t, resp["options"])
}

// TestHandleLoginBegin_WithCreds_CreatesChallenge checks that an authentication challenge is persisted in the DB.
func TestHandleLoginBegin_WithCreds_CreatesChallenge(t *testing.T) {
	testutils.WithTestDB(t)
	withPasskeyConfig(t)
	testutils.WithConfigOverride(t, func() { config.Values.AuthMode = "passkey_only" })

	userID, username := setupPasskeyTestUser(t)
	require.NoError(t, CreatePasskeyCredential(PasskeyCredential{
		ID:         "chal-test-cred",
		UserID:     userID,
		Credential: sampleCredentialJSON(),
	}))

	req := httptest.NewRequest(http.MethodGet,
		"/oauth2/passkey/login/begin?username="+username+"&redirect_uri=http://localhost/cb&state=st1&client_id=c1&scope=openid",
		nil)
	rr := httptest.NewRecorder()
	HandleLoginBegin(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))

	challengeID, _ := resp["challenge_id"].(string)
	require.NotEmpty(t, challengeID)

	// The challenge must exist in DB, be of type authentication, and not yet used
	challenge, err := PasskeyChallengeByID(challengeID)
	require.NoError(t, err)
	assert.Equal(t, "authentication", challenge.Type)
	assert.False(t, challenge.Used)
	assert.True(t, time.Now().Before(challenge.ExpiresAt))
}

// --- HandleLoginFinish ---

func TestHandleLoginFinish_MissingChallengeID(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/passkey/login/finish", nil)
	rr := httptest.NewRecorder()
	HandleLoginFinish(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	var resp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Contains(t, resp["error"], "missing challenge_id")
}

func TestHandleLoginFinish_InvalidChallengeID(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/passkey/login/finish?challenge_id=nonexistent", nil)
	rr := httptest.NewRecorder()
	HandleLoginFinish(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	var resp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Contains(t, resp["error"], "invalid challenge")
}

func TestHandleLoginFinish_ExpiredChallenge(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user-1")

	require.NoError(t, CreatePasskeyChallenge(PasskeyChallenge{
		ID:            "expired-login-challenge",
		UserID:        "user-1",
		ChallengeData: sampleChallengeData(),
		Type:          "authentication",
		LoginState:    `{}`,
		ExpiresAt:     time.Now().Add(-1 * time.Minute),
	}))

	req := httptest.NewRequest(http.MethodPost, "/oauth2/passkey/login/finish?challenge_id=expired-login-challenge", nil)
	rr := httptest.NewRecorder()
	HandleLoginFinish(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	var resp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Contains(t, resp["error"], "expired")
}

func TestHandleLoginFinish_AlreadyUsed(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user-1")

	require.NoError(t, CreatePasskeyChallenge(PasskeyChallenge{
		ID:            "used-login-challenge",
		UserID:        "user-1",
		ChallengeData: sampleChallengeData(),
		Type:          "authentication",
		LoginState:    `{}`,
		ExpiresAt:     time.Now().Add(5 * time.Minute),
		Used:          true,
	}))

	req := httptest.NewRequest(http.MethodPost, "/oauth2/passkey/login/finish?challenge_id=used-login-challenge", nil)
	rr := httptest.NewRecorder()
	HandleLoginFinish(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	var resp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Contains(t, resp["error"], "expired")
}

func TestHandleLoginFinish_WrongType(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user-1")

	// Registration challenge presented to login/finish
	require.NoError(t, CreatePasskeyChallenge(PasskeyChallenge{
		ID:            "reg-challenge-for-login",
		UserID:        "user-1",
		ChallengeData: sampleChallengeData(),
		Type:          "registration",
		LoginState:    `{}`,
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}))

	req := httptest.NewRequest(http.MethodPost, "/oauth2/passkey/login/finish?challenge_id=reg-challenge-for-login", nil)
	rr := httptest.NewRecorder()
	HandleLoginFinish(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	var resp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Contains(t, resp["error"], "invalid challenge")
}

// --- HandleRegisterFinish ---

func TestHandleRegisterFinish_MissingChallengeID(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/passkey/register/finish", nil)
	rr := httptest.NewRecorder()
	HandleRegisterFinish(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	var resp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Contains(t, resp["error"], "missing challenge_id")
}

func TestHandleRegisterFinish_InvalidChallengeID(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/passkey/register/finish?challenge_id=nonexistent", nil)
	rr := httptest.NewRecorder()
	HandleRegisterFinish(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	var resp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Contains(t, resp["error"], "invalid challenge")
}

func TestHandleRegisterFinish_ExpiredChallenge(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user-1")

	require.NoError(t, CreatePasskeyChallenge(PasskeyChallenge{
		ID:            "expired-reg-challenge",
		UserID:        "user-1",
		ChallengeData: sampleChallengeData(),
		Type:          "registration",
		LoginState:    `{}`,
		ExpiresAt:     time.Now().Add(-1 * time.Minute),
	}))

	req := httptest.NewRequest(http.MethodPost, "/oauth2/passkey/register/finish?challenge_id=expired-reg-challenge", nil)
	rr := httptest.NewRecorder()
	HandleRegisterFinish(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	var resp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Contains(t, resp["error"], "expired")
}

func TestHandleRegisterFinish_AlreadyUsed(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user-1")

	require.NoError(t, CreatePasskeyChallenge(PasskeyChallenge{
		ID:            "used-reg-challenge",
		UserID:        "user-1",
		ChallengeData: sampleChallengeData(),
		Type:          "registration",
		LoginState:    `{}`,
		ExpiresAt:     time.Now().Add(5 * time.Minute),
		Used:          true,
	}))

	req := httptest.NewRequest(http.MethodPost, "/oauth2/passkey/register/finish?challenge_id=used-reg-challenge", nil)
	rr := httptest.NewRecorder()
	HandleRegisterFinish(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	var resp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Contains(t, resp["error"], "expired")
}

func TestHandleRegisterFinish_WrongType(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user-1")

	// Authentication challenge presented to register/finish
	require.NoError(t, CreatePasskeyChallenge(PasskeyChallenge{
		ID:            "auth-challenge-for-reg",
		UserID:        "user-1",
		ChallengeData: sampleChallengeData(),
		Type:          "authentication",
		LoginState:    `{}`,
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}))

	req := httptest.NewRequest(http.MethodPost, "/oauth2/passkey/register/finish?challenge_id=auth-challenge-for-reg", nil)
	rr := httptest.NewRecorder()
	HandleRegisterFinish(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	var resp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Contains(t, resp["error"], "invalid challenge")
}
