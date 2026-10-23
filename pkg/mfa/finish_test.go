package mfa

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	"github.com/eugenioenko/autentico/pkg/trusteddevice"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func finishFixture(t *testing.T) (*user.User, LoginState) {
	t.Helper()
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.RequireMfa = true
		config.Values.MfaMethod = "totp"
		config.Values.TrustDeviceEnabled = false
		config.Bootstrap.AuthIdpSessionCookieName = "autentico_idp_session"
	})
	testutils.InsertTestClient(t, "finish", []string{"http://localhost/cb?existing=kept"})
	usr, err := user.CreateUser("finish-user", "Password123!", "finish@example.com")
	require.NoError(t, err)
	_, err = db.GetDB().Exec(`UPDATE clients SET consent_required=TRUE WHERE client_id='finish'`)
	require.NoError(t, err)
	loaded, err := user.UserByID(usr.ID)
	require.NoError(t, err)
	return loaded, LoginState{ClientID: "finish", RedirectURI: "http://localhost/cb?existing=kept", Scope: "openid", State: "opaque & state", CodeChallenge: "challenge", CodeChallengeMethod: "S256"}
}

func requireNoLoginState(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	for _, table := range []string{"idp_sessions", "auth_codes", "user_consents"} {
		var count int
		require.NoError(t, db.GetDB().QueryRow("SELECT COUNT(*) FROM "+table).Scan(&count))
		require.Zero(t, count, table)
	}
	var successes int
	require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM audit_logs WHERE event IN ('login_success','magic_link_login_success')`).Scan(&successes))
	require.Zero(t, successes)
	require.Empty(t, rr.Result().Cookies())
}

func TestFinishLoginEveryPrimaryRequiresLocalMfaBeforeConsent(t *testing.T) {
	for _, primary := range []PrimaryMethod{PrimaryPassword, PrimarySignup, PrimaryPasskey, PrimaryFederation, PrimaryMagicLink, PrimaryVerification} {
		t.Run(string(primary), func(t *testing.T) {
			usr, state := finishFixture(t)
			rr := httptest.NewRecorder()
			next, err := FinishLogin(rr, httptest.NewRequest("GET", "/finish", nil), usr.ID, state, primary)
			require.NoError(t, err)
			target, err := url.Parse(next)
			require.NoError(t, err)
			require.Equal(t, "/oauth2/mfa", target.Path)
			challenge, err := MfaChallengeByIDIncludingExpired(target.Query().Get("challenge_id"))
			require.NoError(t, err)
			require.Equal(t, "totp", challenge.Method)
			require.Equal(t, usr.ID, challenge.UserID)
			requireNoLoginState(t, rr)
		})
	}
}

func TestFinishLoginEveryPrimaryRequiresConsent(t *testing.T) {
	for _, primary := range []PrimaryMethod{PrimaryPassword, PrimarySignup, PrimaryPasskey, PrimaryFederation, PrimaryMagicLink, PrimaryVerification} {
		t.Run(string(primary), func(t *testing.T) {
			usr, state := finishFixture(t)
			config.Values.RequireMfa = false
			rr := httptest.NewRecorder()
			next, err := FinishLogin(rr, httptest.NewRequest("GET", "/finish", nil), usr.ID, state, primary)
			require.NoError(t, err)
			target, err := url.Parse(next)
			require.NoError(t, err)
			require.Equal(t, "/oauth2/consent", target.Path)
			require.Equal(t, state.State, target.Query().Get("state"))
			var count int
			require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM auth_codes`).Scan(&count))
			require.Zero(t, count)
			require.NotEmpty(t, rr.Result().Cookies())
		})
	}
}

func TestFinishLoginEmailProofNeverBypassesVoluntaryTotp(t *testing.T) {
	for _, primary := range []PrimaryMethod{PrimaryMagicLink, PrimaryVerification} {
		t.Run(string(primary), func(t *testing.T) {
			usr, state := finishFixture(t)
			config.Values.RequireMfa = false
			config.Values.MfaMethod = "email"
			_, err := db.GetDB().Exec(`UPDATE users SET totp_verified=TRUE WHERE id=?`, usr.ID)
			require.NoError(t, err)
			rr := httptest.NewRecorder()
			next, err := FinishLogin(rr, httptest.NewRequest("GET", "/finish", nil), usr.ID, state, primary)
			require.NoError(t, err)
			require.Contains(t, next, "/mfa?")
			requireNoLoginState(t, rr)
		})
	}
}

func TestFinishLoginRejectsChangedRegistrationAndDisabledUser(t *testing.T) {
	for _, mutation := range []string{
		`UPDATE clients SET is_active=FALSE`,
		`UPDATE clients SET redirect_uris='["http://different/cb"]'`,
		`UPDATE clients SET scopes='profile'`,
		`UPDATE clients SET grant_types='["refresh_token"]'`,
		`UPDATE users SET deactivated_at=CURRENT_TIMESTAMP`,
	} {
		t.Run(mutation, func(t *testing.T) {
			usr, state := finishFixture(t)
			_, err := db.GetDB().Exec(mutation)
			require.NoError(t, err)
			rr := httptest.NewRecorder()
			_, err = FinishLogin(rr, httptest.NewRequest("GET", "/finish", nil), usr.ID, state, PrimaryFederation)
			require.Error(t, err)
			requireNoLoginState(t, rr)
		})
	}
}

func TestFinishLoginSessionFailureCannotIssueCode(t *testing.T) {
	usr, state := finishFixture(t)
	config.Values.RequireMfa = false
	_, err := db.GetDB().Exec(`CREATE TRIGGER fail_browser_session BEFORE INSERT ON idp_sessions BEGIN SELECT RAISE(ABORT,'test'); END`)
	require.NoError(t, err)
	rr := httptest.NewRecorder()
	_, err = FinishLogin(rr, httptest.NewRequest("GET", "/finish", nil), usr.ID, state, PrimaryPasskey)
	require.Error(t, err)
	requireNoLoginState(t, rr)
}

func TestFinishLoginMissingPublicPkceFailsBeforeMfa(t *testing.T) {
	usr, state := finishFixture(t)
	state.CodeChallenge, state.CodeChallengeMethod = "", ""
	rr := httptest.NewRecorder()
	_, err := FinishLogin(rr, httptest.NewRequest("GET", "/finish", nil), usr.ID, state, PrimaryPassword)
	require.ErrorContains(t, err, "code_challenge")
	requireNoLoginState(t, rr)
}

func TestAlternateLoginTrustedDeviceUsesClientPolicyAndStillRequiresConsent(t *testing.T) {
	for _, allow := range []bool{false, true} {
		t.Run(map[bool]string{true: "allowed", false: "disabled"}[allow], func(t *testing.T) {
			usr, state := finishFixture(t)
			config.Values.TrustDeviceEnabled = !allow
			_, err := db.GetDB().Exec(`UPDATE clients SET trust_device_enabled=? WHERE client_id='finish'`, allow)
			require.NoError(t, err)
			require.NoError(t, trusteddevice.CreateTrustedDevice(trusteddevice.TrustedDevice{ID: "trusted", UserID: usr.ID, ExpiresAt: time.Now().Add(time.Hour)}, "fixture-cookie-token"))
			r := httptest.NewRequest("GET", "/finish", nil)
			r.AddCookie(&http.Cookie{Name: trusteddevice.CookieName, Value: "fixture-cookie-token"})
			rr := httptest.NewRecorder()
			next, err := FinishLogin(rr, r, usr.ID, state, PrimaryFederation)
			require.NoError(t, err)
			if !allow {
				require.Contains(t, next, "/mfa?")
				requireNoLoginState(t, rr)
				return
			}
			require.Contains(t, next, "/consent?")
			var evidence string
			require.NoError(t, db.GetDB().QueryRow(`SELECT mfa_method FROM idp_sessions WHERE user_id=?`, usr.ID).Scan(&evidence))
			require.Equal(t, "trusted_device", evidence)
			var codes int
			require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM auth_codes`).Scan(&codes))
			require.Zero(t, codes)
		})
	}
}

func TestMfaPolicyChangeCannotIssueSessionOrTrustedDevice(t *testing.T) {
	usr, _ := finishFixture(t)
	config.Values.TrustDeviceEnabled = true
	// The stored email challenge predates a change requiring local TOTP.
	require.NoError(t, CreateMfaChallenge(MfaChallenge{ID: "old-policy", UserID: usr.ID,
		Method: "email", Code: utils.HashSHA256("123456"),
		LoginState: `{"client_id":"finish","redirect_uri":"http://localhost/cb?existing=kept","scope":"openid","code_challenge":"challenge","code_challenge_method":"S256"}`,
		ExpiresAt:  time.Now().Add(time.Minute)}))
	form := url.Values{"challenge_id": {"old-policy"}, "code": {"123456"}, "trust_device": {"on"}}
	r := httptest.NewRequest(http.MethodPost, "/oauth2/mfa", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleMfa(rr, r)
	require.Equal(t, http.StatusFound, rr.Code)
	require.Contains(t, rr.Header().Get("Location"), "/authorize?")
	requireNoLoginState(t, rr)
	var count int
	require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM trusted_devices`).Scan(&count))
	require.Zero(t, count)
}

func TestCompletedEmailMfaRecordsEvidenceAndRequiresConsent(t *testing.T) {
	usr, _ := finishFixture(t)
	config.Values.MfaMethod = "email"
	stateJSON := `{"client_id":"finish","redirect_uri":"http://localhost/cb?existing=kept","scope":"openid","state":"opaque & state","code_challenge":"challenge","code_challenge_method":"S256"}`
	require.NoError(t, CreateMfaChallenge(MfaChallenge{ID: "complete", UserID: usr.ID, Method: "email", Code: utils.HashSHA256("123456"), LoginState: stateJSON, ExpiresAt: time.Now().Add(time.Minute)}))
	form := url.Values{"challenge_id": {"complete"}, "code": {"123456"}}
	r := httptest.NewRequest(http.MethodPost, "/oauth2/mfa", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleMfa(rr, r)
	require.Equal(t, http.StatusFound, rr.Code)
	require.Contains(t, rr.Header().Get("Location"), "/consent?")
	var sessionID string
	for _, cookie := range rr.Result().Cookies() {
		if cookie.Name == config.GetBootstrap().AuthIdpSessionCookieName {
			sessionID = cookie.Value
		}
	}
	require.NotEmpty(t, sessionID)
	session, err := idpsession.IdpSessionByID(sessionID)
	require.NoError(t, err)
	require.Equal(t, "email", session.MfaMethod)
	var count int
	require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM auth_codes`).Scan(&count))
	require.Zero(t, count)
}
