package security

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/mfa"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
)

func TestTotpBudgetSharedAcrossHTTPEntryPoints(t *testing.T) {
	ts := startTestServer(t)
	usr := createTestUser(t, "shared-totp", "Password123!", "shared@example.com")
	accountToken := obtainTokensViaROPC(t, ts, "autentico-account", usr.Username, "Password123!")
	const secret = "JBSWY3DPEHPK3PXP"
	require.NoError(t, user.SaveTotpSecret(usr.ID, secret))
	valid, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	passwordGrant := func(code string) (int, string) {
		resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", url.Values{
			"grant_type": {"password"}, "client_id": {"test-client"}, "username": {usr.Username},
			"password": {"Password123!"}, "totp_code": {code},
		})
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		return resp.StatusCode, string(body)
	}
	browser := func(challengeID, code string) (int, string) {
		// Each fresh challenge is a separate login, with the real CSRF form flow.
		require.NoError(t, mfa.CreateMfaChallenge(mfa.MfaChallenge{ID: challengeID, UserID: usr.ID,
			Method: "totp", ExpiresAt: time.Now().Add(time.Minute),
			LoginState: `{"client_id":"test-client","redirect_uri":"http://localhost:3000/callback","scope":"openid profile email"}`}))
		resp, err := ts.Client.Get(ts.BaseURL + "/oauth2/mfa?challenge_id=" + challengeID)
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		require.Equal(t, http.StatusOK, resp.StatusCode)
		csrf := getCSRFToken(string(body))
		require.NotEmpty(t, csrf)
		form := url.Values{"challenge_id": {challengeID}, "code": {code}, "gorilla.csrf.Token": {csrf}}
		req, err := http.NewRequest(http.MethodPost, ts.BaseURL+"/oauth2/mfa", strings.NewReader(form.Encode()))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Referer", ts.BaseURL+"/oauth2/mfa")
		resp, err = ts.Client.Do(req)
		require.NoError(t, err)
		body, err = io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		return resp.StatusCode, resp.Header.Get("Location") + string(body)
	}
	remove := func(code string) (int, string) {
		body, err := json.Marshal(map[string]string{"current_password": "Password123!", "code": code})
		require.NoError(t, err)
		status, response := doAccountRequest(t, ts, http.MethodDelete, accountToken.AccessToken, "/account/api/mfa/totp", string(body))
		return status, string(response)
	}
	for range 2 {
		status, body := passwordGrant("invalid")
		require.Equal(t, http.StatusForbidden, status)
		require.Contains(t, body, "invalid_mfa_code")
	}
	for _, id := range []string{"fresh-one", "fresh-two"} {
		status, body := browser(id, "invalid")
		require.Equal(t, http.StatusOK, status)
		require.Contains(t, body, "Invalid verification code")
	}
	status, body := remove("invalid")
	require.Equal(t, http.StatusForbidden, status)
	require.Contains(t, body, "mfa_locked")
	status, body = passwordGrant(valid)
	require.Equal(t, http.StatusForbidden, status)
	require.Contains(t, body, "mfa_locked")
	status, body = browser("fresh-locked", valid)
	require.Equal(t, http.StatusFound, status)
	require.Contains(t, body, "Too+many+failed+TOTP+attempts")
	status, body = remove(valid)
	require.Equal(t, http.StatusForbidden, status)
	require.Contains(t, body, "mfa_locked")
	var attempts int
	require.NoError(t, db.GetDB().QueryRow(`SELECT totp_failed_attempts FROM users WHERE id=?`, usr.ID).Scan(&attempts))
	require.Equal(t, 5, attempts)
	current, err := user.UserByID(usr.ID)
	require.NoError(t, err)
	require.True(t, current.TotpVerified)
	_, err = db.GetDB().Exec(`UPDATE users SET totp_locked_until=? WHERE id=?`, time.Now().Add(-time.Second), usr.ID)
	require.NoError(t, err)
	status, body = remove(valid)
	require.Equal(t, http.StatusOK, status, body)
}
