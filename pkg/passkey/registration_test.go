package passkey

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/stretchr/testify/require"
)

func TestRegistrationPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, mode, override, email, smtp string
		allow, verify                     bool
		want                              int
	}{
		{name: "signup disabled", mode: "password_and_passkey", want: 403},
		{name: "password only", mode: "password", allow: true, want: 403},
		{name: "both methods", mode: "password_and_passkey", allow: true, want: 200},
		{name: "passkey only", mode: "passkey_only", allow: true, want: 200},
		{name: "client disables signup", mode: "passkey_only", allow: true, override: "0", want: 403},
		{name: "client enables signup", mode: "passkey_only", override: "1", want: 200},
		{name: "verification needs email", mode: "passkey_only", allow: true, verify: true, smtp: "smtp.example.com", want: 400},
		{name: "verification needs SMTP", mode: "passkey_only", allow: true, verify: true, email: "a@example.com", want: 503},
		{name: "verification configured", mode: "passkey_only", allow: true, verify: true, email: "a@example.com", smtp: "smtp.example.com", want: 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withPasskeyTestDB(t)
			withPasskeyConfig(t)
			config.Values.AuthAllowSelfSignup, config.Values.AuthMode = tc.allow, tc.mode
			config.Values.RequireEmailVerification, config.Values.SmtpHost = tc.verify, tc.smtp
			if tc.override != "" {
				_, err := db.GetDB().Exec("UPDATE clients SET allow_self_signup = ? WHERE client_id='c1'", tc.override)
				require.NoError(t, err)
			}
			r := httptest.NewRequest("GET", signedPasskeyURL("/oauth2/passkey/register/begin?username=policy-user&email="+tc.email), nil)
			w := httptest.NewRecorder()
			HandleRegisterBegin(w, r)
			require.Equal(t, tc.want, w.Code, w.Body.String())
			var n int
			require.NoError(t, db.GetDB().QueryRow("SELECT COUNT(*) FROM users").Scan(&n))
			if tc.want == 200 {
				require.Equal(t, 1, n)
			} else {
				require.Zero(t, n, "policy must reject before creating accounts")
			}
		})
	}
}

func beginOwnedRegistration(t *testing.T, name string, owner *http.Cookie) (string, *http.Cookie, string) {
	t.Helper()
	r := httptest.NewRequest("GET", signedPasskeyURL("/oauth2/passkey/register/begin?username="+name), nil)
	if owner != nil {
		r.AddCookie(owner)
	}
	w := httptest.NewRecorder()
	HandleRegisterBegin(w, r)
	require.Equal(t, 200, w.Code, w.Body.String())
	var response struct {
		ChallengeID string `json:"challenge_id"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	usr, err := user.UserByUsername(name)
	require.NoError(t, err)
	return response.ChallengeID, cookies[0], usr.ID
}

func TestRegistrationOwnership(t *testing.T) {
	withPasskeyTestDB(t)
	withPasskeyConfig(t)
	challengeID, cookie, originalID := beginOwnedRegistration(t, "owned-user", nil)
	require.True(t, cookie.HttpOnly)
	require.Equal(t, http.SameSiteStrictMode, cookie.SameSite)
	require.Equal(t, "/", cookie.Path)
	require.Empty(t, cookie.Domain)
	require.Equal(t, 300, cookie.MaxAge)

	for _, owner := range []string{"", "another-browser"} {
		r := httptest.NewRequest("GET", signedPasskeyURL("/oauth2/passkey/register/begin?username=owned-user&email=attacker@example.com"), nil)
		r.AddCookie(&http.Cookie{Name: registrationCookieName(), Value: owner})
		w := httptest.NewRecorder()
		HandleRegisterBegin(w, r)
		require.Equal(t, http.StatusConflict, w.Code)
		usr, err := user.UserByUsername("owned-user")
		require.NoError(t, err)
		require.Equal(t, originalID, usr.ID)
		require.Empty(t, usr.Email)

		r = httptest.NewRequest("POST", "/oauth2/passkey/register/finish?challenge_id="+challengeID, strings.NewReader(`{}`))
		r.AddCookie(&http.Cookie{Name: registrationCookieName(), Value: owner})
		w = httptest.NewRecorder()
		HandleRegisterFinish(w, r)
		require.Equal(t, http.StatusForbidden, w.Code)
		_, err = user.UserByID(originalID)
		require.NoError(t, err, "an unbound finish must never delete the pending user")
	}
	_, nextCookie, nextID := beginOwnedRegistration(t, "owned-user", cookie)
	require.NotEqual(t, originalID, nextID)
	require.NotEqual(t, cookie.Value, nextCookie.Value)
	_, err := PasskeyChallengeByIDIncludingExpired(challengeID)
	require.Error(t, err, "retry invalidates the previous ceremony")
}

func TestRegistrationCookieSecurePrefix(t *testing.T) {
	withPasskeyTestDB(t)
	withPasskeyConfig(t)
	config.Bootstrap.AuthCSRFSecureCookie = true
	_, cookie, _ := beginOwnedRegistration(t, "secure-user", nil)
	require.Equal(t, "__Host-autentico_passkey_registration", cookie.Name)
	require.True(t, cookie.Secure)
}

func TestRegistrationFinishRechecksPolicy(t *testing.T) {
	for _, setting := range []string{"signup", "mode", "client override", "verification"} {
		t.Run(setting, func(t *testing.T) {
			withPasskeyTestDB(t)
			withPasskeyConfig(t)
			id, cookie, userID := beginOwnedRegistration(t, "policy-change", nil)
			want := 403
			switch setting {
			case "signup":
				config.Values.AuthAllowSelfSignup = false
			case "mode":
				config.Values.AuthMode = "password"
			case "client override":
				_, err := db.GetDB().Exec("UPDATE clients SET allow_self_signup=FALSE WHERE client_id='c1'")
				require.NoError(t, err)
			case "verification":
				config.Values.RequireEmailVerification = true
				want = 400
			}
			r := httptest.NewRequest("POST", "/oauth2/passkey/register/finish?challenge_id="+id, strings.NewReader(`{}`))
			r.AddCookie(cookie)
			w := httptest.NewRecorder()
			HandleRegisterFinish(w, r)
			require.Equal(t, want, w.Code, w.Body.String())
			_, err := user.UserByID(userID)
			require.NoError(t, err)
			challenge, err := PasskeyChallengeByIDIncludingExpired(id)
			require.NoError(t, err)
			require.False(t, challenge.Used)
		})
	}
}

func TestPendingRegistrationDeletionGuards(t *testing.T) {
	for _, protect := range []string{"password", "registered", "credential", "live challenge", "recent account", "expired"} {
		t.Run(protect, func(t *testing.T) {
			withPasskeyTestDB(t)
			withPasskeyConfig(t)
			setupPendingPasskeyUser(t, "pending", "pending")
			_, err := db.GetDB().Exec("UPDATE users SET created_at=datetime('now','-10 minutes') WHERE id='pending'")
			require.NoError(t, err)
			switch protect {
			case "password":
				_, err = db.GetDB().Exec("UPDATE users SET password='hashed' WHERE id='pending'")
			case "registered":
				err = user.SetRegisteredAt("pending")
			case "credential":
				err = CreatePasskeyCredential(PasskeyCredential{ID: "saved", UserID: "pending", Name: "saved", Credential: "{}"})
			case "live challenge":
				err = CreatePasskeyChallenge(PasskeyChallenge{ID: "live", UserID: "pending", Type: "registration", ExpiresAt: time.Now().Add(time.Minute)})
			case "recent account":
				_, err = db.GetDB().Exec("UPDATE users SET created_at=CURRENT_TIMESTAMP WHERE id='pending'")
			}
			require.NoError(t, err)
			deleted, err := deletePendingRegistration("pending", "wrong-cookie")
			require.NoError(t, err)
			require.Equal(t, protect == "expired", deleted)
		})
	}
}

func TestPasskeyUnverifiedLoginCannotIssueSession(t *testing.T) {
	withPasskeyTestDB(t)
	withPasskeyConfig(t)
	config.Values.RequireEmailVerification = true
	id, _ := setupPasskeyTestUser(t)
	usr, err := user.UserByID(id)
	require.NoError(t, err)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", nil)
	redirect, err := completeAuthFlow(w, r, usr, `{"client_id":"c1","redirect_uri":"http://localhost/cb","scope":"openid","code_challenge":"challenge","code_challenge_method":"S256"}`)
	require.NoError(t, err)
	require.Contains(t, redirect, "/verify-email/pending?")
	require.NotContains(t, redirect, "token=")
	require.Empty(t, w.Result().Cookies())
	for _, table := range []string{"auth_codes", "idp_sessions", "sessions"} {
		var n int
		require.NoError(t, db.GetDB().QueryRow("SELECT COUNT(*) FROM "+table).Scan(&n))
		require.Zero(t, n, table)
	}
}
