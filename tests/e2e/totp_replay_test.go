package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/mfa"
	"github.com/eugenioenko/autentico/pkg/token"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
)

func TestTotpReplayAcrossPasswordBrowserAndAccountHTTP(t *testing.T) {
	ts := startTestServer(t)
	usr := createTestUser(t, "replay@example.com", "password123", "replay@example.com")
	const secret = "JBSWY3DPEHPK3PXP"
	require.NoError(t, user.SaveTotpSecret(usr.ID, secret))
	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	form := url.Values{
		"grant_type": {"password"}, "client_id": {"autentico-account"},
		"username": {usr.Username}, "password": {"password123"}, "totp_code": {code},
	}
	resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var issued token.TokenResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&issued))
	require.NoError(t, resp.Body.Close())
	resp, err = ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
	require.NoError(t, resp.Body.Close())

	// A fresh browser challenge must share the same enrollment's replay state.
	require.NoError(t, mfa.CreateMfaChallenge(mfa.MfaChallenge{
		ID: "cross-path", UserID: usr.ID, Method: "totp", ExpiresAt: time.Now().Add(time.Minute),
		LoginState: `{"client_id":"test-client","redirect_uri":"http://localhost:3000/callback","scope":"openid","code_challenge":"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM","code_challenge_method":"S256"}`,
	}))
	resp, err = ts.Client.Get(ts.BaseURL + "/oauth2/mfa?challenge_id=cross-path")
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	csrf := getCSRFToken(string(body))
	require.NotEmpty(t, csrf)
	form = url.Values{"challenge_id": {"cross-path"}, "code": {code}, "gorilla.csrf.Token": {csrf}}
	req, err := http.NewRequest(http.MethodPost, ts.BaseURL+"/oauth2/mfa", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", ts.BaseURL+"/oauth2/mfa")
	resp, err = ts.Client.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Contains(t, string(body), "Invalid verification code")

	// A valid MFA session must still present a fresh code to disable MFA.
	body, err = json.Marshal(map[string]string{"current_password": "password123", "code": code})
	require.NoError(t, err)
	req, err = http.NewRequest(http.MethodDelete, ts.BaseURL+"/account/api/mfa/totp", strings.NewReader(string(body)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+issued.AccessToken)
	resp, err = ts.Client.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
	require.NoError(t, resp.Body.Close())
	current, err := user.UserByID(usr.ID)
	require.NoError(t, err)
	require.True(t, current.TotpVerified)
}

func TestStaleBrowserEnrollmentCannotReplaceAccountSetupHTTP(t *testing.T) {
	ts := startTestServer(t)
	usr := createTestUser(t, "enrollment@example.com", "password123", "enrollment@example.com")
	issued := obtainTokensViaPasswordGrantForClient(t, ts, "autentico-account", usr.Username, "password123")
	require.NoError(t, mfa.CreateMfaChallenge(mfa.MfaChallenge{
		ID: "stale-enrollment", UserID: usr.ID, Method: "totp", ExpiresAt: time.Now().Add(time.Minute),
		LoginState: `{"client_id":"test-client","redirect_uri":"http://localhost:3000/callback","scope":"openid","code_challenge":"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM","code_challenge_method":"S256"}`,
	}))
	resp, err := ts.Client.Get(ts.BaseURL + "/oauth2/mfa?challenge_id=stale-enrollment")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	csrf := getCSRFToken(string(body))
	require.NotEmpty(t, csrf)
	old, err := user.UserByID(usr.ID)
	require.NoError(t, err)
	require.NotEmpty(t, old.TotpSecret)
	require.Contains(t, string(body), old.TotpSecret)
	code, err := totp.GenerateCode(old.TotpSecret, time.Now())
	require.NoError(t, err)

	// A newer, password-confirmed account setup replaces the pending browser seed.
	req, err := http.NewRequest(http.MethodPost, ts.BaseURL+"/account/api/mfa/totp/setup", strings.NewReader(`{"current_password":"password123"}`))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+issued.AccessToken)
	resp, err = ts.Client.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.NoError(t, resp.Body.Close())
	pending, err := user.UserByID(usr.ID)
	require.NoError(t, err)
	require.NotEqual(t, old.TotpSecret, pending.TotpSecret)

	form := url.Values{"challenge_id": {"stale-enrollment"}, "totp_secret": {old.TotpSecret}, "code": {code}, "gorilla.csrf.Token": {csrf}}
	req, err = http.NewRequest(http.MethodPost, ts.BaseURL+"/oauth2/mfa", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", ts.BaseURL+"/oauth2/mfa")
	resp, err = ts.Client.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Contains(t, string(body), "Invalid verification code or enrollment changed")
	current, err := user.UserByID(usr.ID)
	require.NoError(t, err)
	require.False(t, current.TotpVerified)
	require.Equal(t, pending.TotpSecret, current.TotpSecret, "stale form must preserve the newer pending setup")

	// The newer enrollment still confirms successfully with its own code.
	freshCode, err := totp.GenerateCode(pending.TotpSecret, time.Now())
	require.NoError(t, err)
	payload, err := json.Marshal(map[string]string{"code": freshCode})
	require.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, ts.BaseURL+"/account/api/mfa/totp/verify", strings.NewReader(string(payload)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+issued.AccessToken)
	resp, err = ts.Client.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.NoError(t, resp.Body.Close())
}
