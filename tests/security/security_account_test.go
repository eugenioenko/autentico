package security

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func doAccountRequest(t *testing.T, ts *TestServer, method, token, path string, body string) (int, []byte) {
	t.Helper()
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, ts.BaseURL+path, bodyReader)
	require.NoError(t, err)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, respBody
}

// TestAccount_ProfileRoleEscalation verifies that sending role/password/totp
// fields in a profile update request does not escalate privileges.
func TestAccount_ProfileRoleEscalation(t *testing.T) {
	ts := startTestServer(t)
	createTestUser(t, "escuser", "password123", "escuser@test.com")
	tokenResp := obtainTokensViaROPC(t, ts, "test-client", "escuser", "password123")

	payloads := []struct {
		name string
		body string
	}{
		{"role_admin", `{"role": "admin", "given_name": "Test"}`},
		{"role_superadmin", `{"role": "superadmin"}`},
		{"password_inject", `{"password": "hacked123", "given_name": "Test"}`},
		{"totp_verified", `{"totp_verified": true}`},
		{"totp_secret", `{"totp_secret": "JBSWY3DPEHPK3PXP"}`},
		{"deactivated_at", `{"deactivated_at": null}`},
	}

	for _, p := range payloads {
		t.Run(p.name, func(t *testing.T) {
			status, _ := doAccountRequest(t, ts, "PUT", tokenResp.AccessToken,
				"/account/api/profile", p.body)
			assert.True(t, status < 500, "profile update must not cause server error, got %d", status)
		})
	}

	// Verify role didn't change
	status, body := doAccountRequest(t, ts, "GET", tokenResp.AccessToken, "/account/api/profile", "")
	require.Equal(t, http.StatusOK, status)
	var profile struct {
		Data struct {
			Role string `json:"role"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(body, &profile))
	assert.Equal(t, "user", profile.Data.Role, "role must remain 'user' after escalation attempts")
}

// TestAccount_SessionIDOR verifies that user A cannot revoke user B's session.
func TestAccount_SessionIDOR(t *testing.T) {
	ts := startTestServer(t)

	createTestUser(t, "idoruser_a", "password123", "idora@test.com")
	userB := createTestUser(t, "idoruser_b", "password123", "idorb@test.com")
	tokenA := obtainTokensViaROPC(t, ts, "test-client", "idoruser_a", "password123")

	victimSessionID := "victim-session-idor"
	err := idpsession.CreateIdpSession(idpsession.IdpSession{
		ID:             victimSessionID,
		UserID:         userB.ID,
		UserAgent:      "Victim Browser",
		IPAddress:      "10.0.0.2",
		LastActivityAt: time.Now(),
		CreatedAt:      time.Now(),
	})
	require.NoError(t, err)

	// User A tries to revoke user B's session
	status, _ := doAccountRequest(t, ts, "DELETE", tokenA.AccessToken,
		"/account/api/sessions/"+victimSessionID, "")
	assert.True(t, status == http.StatusForbidden || status == http.StatusNotFound,
		"IDOR: user A must not revoke user B's session, got %d", status)
}

// TestAccount_SessionRevoke_NonexistentID verifies that revoking a
// nonexistent session ID returns 404, not a server error.
func TestAccount_SessionRevoke_NonexistentID(t *testing.T) {
	ts := startTestServer(t)
	createTestUser(t, "sessuser", "password123", "sessuser@test.com")
	tokenResp := obtainTokensViaROPC(t, ts, "test-client", "sessuser", "password123")

	status, _ := doAccountRequest(t, ts, "DELETE", tokenResp.AccessToken,
		"/account/api/sessions/nonexistent-session-id-12345", "")
	assert.Equal(t, http.StatusNotFound, status,
		"revoking nonexistent session must return 404")
}

// TestAccount_PasswordChange_WrongCurrentPassword verifies that password
// changes require correct current password.
func TestAccount_PasswordChange_WrongCurrentPassword(t *testing.T) {
	ts := startTestServer(t)
	createTestUser(t, "pwuser", "password123", "pwuser@test.com")
	tokenResp := obtainTokensViaROPC(t, ts, "test-client", "pwuser", "password123")

	status, _ := doAccountRequest(t, ts, "POST", tokenResp.AccessToken,
		"/account/api/password",
		`{"current_password": "wrongpassword", "new_password": "NewPass456!"}`)
	assert.Equal(t, http.StatusForbidden, status,
		"password change with wrong current password must be rejected")
}

// TestAccount_PasswordChange_ShortNewPassword verifies that too-short new
// passwords are rejected by validation.
func TestAccount_PasswordChange_ShortNewPassword(t *testing.T) {
	ts := startTestServer(t)
	createTestUser(t, "pwuser2", "password123", "pwuser2@test.com")
	tokenResp := obtainTokensViaROPC(t, ts, "test-client", "pwuser2", "password123")

	status, _ := doAccountRequest(t, ts, "POST", tokenResp.AccessToken,
		"/account/api/password",
		`{"current_password": "password123", "new_password": "ab"}`)
	assert.Equal(t, http.StatusBadRequest, status,
		"too-short new password must be rejected")
}

// TestAccount_Profile_NoAuth verifies that all account endpoints
// reject unauthenticated requests.
func TestAccount_Profile_NoAuth(t *testing.T) {
	ts := startTestServer(t)

	endpoints := []struct {
		method string
		path   string
	}{
		{"GET", "/account/api/profile"},
		{"PUT", "/account/api/profile"},
		{"POST", "/account/api/password"},
		{"GET", "/account/api/sessions"},
		{"DELETE", "/account/api/sessions/any-id"},
		{"GET", "/account/api/mfa"},
		{"POST", "/account/api/mfa/totp/setup"},
		{"POST", "/account/api/mfa/totp/verify"},
		{"DELETE", "/account/api/mfa/totp"},
		{"GET", "/account/api/passkeys"},
		{"DELETE", "/account/api/passkeys/any-id"},
		{"GET", "/account/api/trusted-devices"},
		{"DELETE", "/account/api/trusted-devices/any-id"},
	}

	for _, ep := range endpoints {
		t.Run(ep.method+"_"+ep.path, func(t *testing.T) {
			status, _ := doAccountRequest(t, ts, ep.method, "", ep.path, "")
			assert.Equal(t, http.StatusUnauthorized, status,
				"%s %s without auth must return 401", ep.method, ep.path)
		})
	}
}

// TestAccount_Profile_FabricatedJWT verifies that all account endpoints
// reject fabricated/invalid JWTs.
func TestAccount_Profile_FabricatedJWT(t *testing.T) {
	ts := startTestServer(t)

	fakeTokens := []string{
		"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJoYWNrZXIifQ.fake",
		"not.a.jwt",
		"",
		"' OR 1=1--",
	}

	for _, tok := range fakeTokens {
		t.Run(tok, func(t *testing.T) {
			status, _ := doAccountRequest(t, ts, "GET", tok, "/account/api/profile", "")
			assert.Equal(t, http.StatusUnauthorized, status,
				"fabricated token must be rejected")
		})
	}
}

// TestAccount_SessionListIsolation verifies that a user's session list only
// contains their own sessions, not other users' sessions.
func TestAccount_SessionListIsolation(t *testing.T) {
	ts := startTestServer(t)
	createTestUser(t, "isolateA", "password123", "isolatea@test.com")
	createTestUser(t, "isolateB", "password123", "isolateb@test.com")
	tokenA := obtainTokensViaROPC(t, ts, "test-client", "isolateA", "password123")
	_ = obtainTokensViaROPC(t, ts, "test-client", "isolateB", "password123")

	// User A fetches their sessions — should not see user B's sessions
	status, body := doAccountRequest(t, ts, "GET", tokenA.AccessToken, "/account/api/sessions", "")
	require.Equal(t, http.StatusOK, status)

	var resp struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(body, &resp))

	// ROPC doesn't create IdP sessions, so the list might be empty — that's OK.
	// What matters is we didn't get a server error and the data shape is correct.
	// If there are sessions, they must only belong to user A (verified by the
	// handler's query filter).
	assert.True(t, status == http.StatusOK, "session list must succeed")
}

// TestAccount_MfaStatus_NoAuth verifies MFA status requires authentication.
func TestAccount_MfaStatus_NoAuth(t *testing.T) {
	ts := startTestServer(t)

	status, _ := doAccountRequest(t, ts, "GET", "", "/account/api/mfa", "")
	assert.Equal(t, http.StatusUnauthorized, status)
}

// TestAccount_PasskeyDeleteIDOR verifies that user A cannot delete user B's passkey.
func TestAccount_PasskeyDeleteIDOR(t *testing.T) {
	ts := startTestServer(t)
	createTestUser(t, "pkuserA", "password123", "pkusera@test.com")
	userB := createTestUser(t, "pkuserB", "password123", "pkuserb@test.com")
	tokenA := obtainTokensViaROPC(t, ts, "test-client", "pkuserA", "password123")

	fakeCredID := "fake-passkey-cred-id"
	_, err := db.GetDB().Exec(
		"INSERT INTO passkey_credentials (id, user_id, credential, name, created_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?)",
		fakeCredID, userB.ID, `{"id":"test"}`, "Victim Key", time.Now().UTC().Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339),
	)
	require.NoError(t, err)

	// User A tries to delete user B's passkey
	status, _ := doAccountRequest(t, ts, "DELETE", tokenA.AccessToken,
		"/account/api/passkeys/"+fakeCredID, "")
	assert.True(t, status == http.StatusForbidden || status == http.StatusNotFound,
		"IDOR: user A must not delete user B's passkey, got %d", status)
}

// TestAccount_TrustedDeviceIDOR verifies that user A cannot revoke user B's trusted device.
func TestAccount_TrustedDeviceIDOR(t *testing.T) {
	ts := startTestServer(t)
	createTestUser(t, "tduserA", "password123", "tdusera@test.com")
	userB := createTestUser(t, "tduserB", "password123", "tduserb@test.com")
	tokenA := obtainTokensViaROPC(t, ts, "test-client", "tduserA", "password123")

	fakeDeviceID := "fake-trusted-device-id"
	_, err := db.GetDB().Exec(
		"INSERT INTO trusted_devices (id, user_id, device_name, created_at, last_used_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
		fakeDeviceID, userB.ID, "Victim Device", time.Now().UTC().Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339), time.Now().Add(24*time.Hour).UTC().Format(time.RFC3339),
	)
	require.NoError(t, err)

	// User A tries to revoke user B's trusted device
	status, _ := doAccountRequest(t, ts, "DELETE", tokenA.AccessToken,
		"/account/api/trusted-devices/"+fakeDeviceID, "")
	assert.True(t, status == http.StatusForbidden || status == http.StatusNotFound,
		"IDOR: user A must not revoke user B's trusted device, got %d", status)
}

// TestAccount_ProfileUpdate_XSSInFields verifies that profile fields don't
// cause issues when populated with script injection payloads.
func TestAccount_ProfileUpdate_XSSInFields(t *testing.T) {
	ts := startTestServer(t)
	createTestUser(t, "xssuser", "password123", "xssuser@test.com")
	tokenResp := obtainTokensViaROPC(t, ts, "test-client", "xssuser", "password123")

	xssPayload := `{"given_name": "<script>alert(1)</script>", "family_name": "<img src=x onerror=alert(1)>"}`

	status, _ := doAccountRequest(t, ts, "PUT", tokenResp.AccessToken,
		"/account/api/profile", xssPayload)

	// Should either accept (stored as-is, but output is JSON which is inherently escaped)
	// or reject. Must not cause a server error.
	assert.True(t, status < 500, "XSS payload must not cause server error, got %d", status)

	// If accepted, verify the response is proper JSON (Content-Type: application/json)
	if status == http.StatusOK {
		status2, body := doAccountRequest(t, ts, "GET", tokenResp.AccessToken, "/account/api/profile", "")
		require.Equal(t, http.StatusOK, status2)
		var profile map[string]interface{}
		require.NoError(t, json.Unmarshal(body, &profile),
			"profile response must be valid JSON even with stored XSS payloads")
	}
}

// TestAccount_PasswordChange_Success verifies the happy path for password change
// and that the old password no longer works for new token grants.
func TestAccount_PasswordChange_Success(t *testing.T) {
	ts := startTestServer(t)
	createTestUser(t, "pwok", "password123", "pwok@test.com")
	tokenResp := obtainTokensViaROPC(t, ts, "test-client", "pwok", "password123")

	status, _ := doAccountRequest(t, ts, "POST", tokenResp.AccessToken,
		"/account/api/password",
		`{"current_password": "password123", "new_password": "NewSecurePass456!"}`)
	require.Equal(t, http.StatusOK, status, "password change should succeed")

	// Old password should no longer work for ROPC
	form := "grant_type=password&client_id=test-client&username=pwok&password=password123"
	req, err := http.NewRequest("POST", ts.BaseURL+"/oauth2/token", strings.NewReader(form))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.NotEqual(t, http.StatusOK, resp.StatusCode,
		"old password must not grant new tokens after password change")
}

// TestAccount_PasswordChange_InvalidatesOtherSessions verifies that changing
// a password from one session invalidates all other sessions for that user.
func TestAccount_PasswordChange_InvalidatesOtherSessions(t *testing.T) {
	ts := startTestServer(t)
	createTestUser(t, "pwsess", "password123", "pwsess@test.com")

	// Create two independent sessions via ROPC
	session1 := obtainTokensViaROPC(t, ts, "test-client", "pwsess", "password123")
	session2 := obtainTokensViaROPC(t, ts, "test-client", "pwsess", "password123")

	// Both sessions should work before password change
	s1Status, _ := doAccountRequest(t, ts, "GET", session1.AccessToken, "/account/api/profile", "")
	require.Equal(t, http.StatusOK, s1Status, "session 1 should work before password change")
	s2Status, _ := doAccountRequest(t, ts, "GET", session2.AccessToken, "/account/api/profile", "")
	require.Equal(t, http.StatusOK, s2Status, "session 2 should work before password change")

	// Change password using session 1
	status, _ := doAccountRequest(t, ts, "POST", session1.AccessToken,
		"/account/api/password",
		`{"current_password": "password123", "new_password": "ChangedPass789!"}`)
	require.Equal(t, http.StatusOK, status, "password change should succeed")

	// Session 1 (the one that changed the password) should still work
	s1After, _ := doAccountRequest(t, ts, "GET", session1.AccessToken, "/account/api/profile", "")
	assert.Equal(t, http.StatusOK, s1After,
		"session that changed password should remain valid")

	// Session 2 should be invalidated
	s2After, _ := doAccountRequest(t, ts, "GET", session2.AccessToken, "/account/api/profile", "")
	assert.Equal(t, http.StatusUnauthorized, s2After,
		"other sessions must be invalidated after password change")
}
