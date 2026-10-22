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
	"github.com/eugenioenko/autentico/pkg/trusteddevice"
	"github.com/eugenioenko/autentico/pkg/utils"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestMfaClientTrustedDeviceOverride(t *testing.T) {
	for _, allow := range []bool{false, true} {
		t.Run(map[bool]string{false: "deny", true: "allow"}[allow], func(t *testing.T) {
			testutils.WithTestDB(t)
			testutils.InsertTestUser(t, "user-1")
			testutils.InsertTestClient(t, "stored-client", []string{"http://localhost/cb"})
			testutils.InsertTestClient(t, "posted-client", []string{"http://localhost/cb"})
			testutils.WithConfigOverride(t, func() {
				config.Values.AuthAuthorizationCodeExpiration = 10 * time.Minute
				config.Values.TrustDeviceEnabled = !allow
				config.Values.TrustDeviceExpiration = 30 * 24 * time.Hour
			})
			_, err := db.GetDB().Exec(`UPDATE clients SET trust_device_enabled=?,trust_device_expiration='48h' WHERE client_id='stored-client'; UPDATE clients SET trust_device_enabled=? WHERE client_id='posted-client'`, allow, !allow)
			require.NoError(t, err)
			now := time.Now().UTC()
			require.NoError(t, CreateMfaChallenge(MfaChallenge{ID: "override", UserID: "user-1", Method: "email", Code: utils.HashSHA256("123456"), LoginState: `{"client_id":"stored-client","redirect_uri":"http://localhost/cb","scope":"openid","code_challenge":"challenge","code_challenge_method":"S256"}`, ExpiresAt: now.Add(time.Hour)}))
			_, err = db.GetDB().Exec(`UPDATE mfa_challenges SET otp_sent_at=? WHERE id='override'`, now)
			require.NoError(t, err)
			get := httptest.NewRecorder()
			HandleMfa(get, httptest.NewRequest(http.MethodGet, "/oauth2/mfa?challenge_id=override&client_id=posted-client", nil))
			require.Equal(t, http.StatusOK, get.Code)
			require.Equal(t, allow, strings.Contains(get.Body.String(), `name="trust_device"`))
			if allow {
				require.Contains(t, get.Body.String(), "Trust this device for 2 days")
			}
			// Client policy may change after rendering. POST always resolves it again.
			_, err = db.GetDB().Exec(`UPDATE clients SET trust_device_expiration='72h',authorization_code_expiration='2m' WHERE client_id='stored-client'`)
			require.NoError(t, err)
			form := url.Values{"challenge_id": {"override"}, "code": {"123456"}, "trust_device": {"on"}, "client_id": {"posted-client"}}
			req := httptest.NewRequest(http.MethodPost, "/oauth2/mfa", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()
			HandleMfa(rr, req)
			require.Equal(t, http.StatusFound, rr.Code, rr.Body.String())
			target, err := url.Parse(rr.Header().Get("Location"))
			require.NoError(t, err)
			var codeExpiry time.Time
			require.NoError(t, db.GetDB().QueryRow(`SELECT expires_at FROM auth_codes WHERE code=?`, target.Query().Get("code")).Scan(&codeExpiry))
			require.WithinDuration(t, time.Now().Add(2*time.Minute), codeExpiry, time.Second)
			var device *http.Cookie
			for _, cookie := range rr.Result().Cookies() {
				if cookie.Name == trusteddevice.CookieName {
					device = cookie
				}
			}
			var count int
			require.NoError(t, db.GetDB().QueryRow(`SELECT count(*) FROM trusted_devices`).Scan(&count))
			if allow {
				require.NotNil(t, device)
				require.Equal(t, 72*3600, device.MaxAge)
				require.Equal(t, 1, count)
				var expiry time.Time
				require.NoError(t, db.GetDB().QueryRow(`SELECT expires_at FROM trusted_devices WHERE id=?`, device.Value).Scan(&expiry))
				require.WithinDuration(t, time.Now().Add(72*time.Hour), expiry, time.Second)
			} else {
				require.Nil(t, device)
				require.Zero(t, count)
			}
		})
	}
}

func TestMfaUnavailableClientDoesNotUseGlobalPolicy(t *testing.T) {
	for _, state := range []string{`{`, `{}`, `{"client_id":"missing"}`, `{"client_id":"inactive"}`} {
		t.Run(state, func(t *testing.T) {
			testutils.WithTestDB(t)
			testutils.InsertTestUser(t, "user-1")
			testutils.InsertTestClient(t, "inactive", []string{"http://localhost/cb"})
			testutils.WithConfigOverride(t, func() { config.Values.TrustDeviceEnabled = true })
			_, err := db.GetDB().Exec(`UPDATE clients SET is_active=FALSE WHERE client_id='inactive'`)
			require.NoError(t, err)
			require.NoError(t, CreateMfaChallenge(MfaChallenge{ID: "unavailable", UserID: "user-1", Method: "email", Code: utils.HashSHA256("123456"), LoginState: state, ExpiresAt: time.Now().Add(time.Hour)}))
			form := url.Values{"challenge_id": {"unavailable"}, "code": {"123456"}, "trust_device": {"on"}}
			req := httptest.NewRequest(http.MethodPost, "/oauth2/mfa", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()
			HandleMfa(rr, req)
			require.Equal(t, http.StatusFound, rr.Code)
			require.Contains(t, rr.Header().Get("Location"), "Verification+client+is+unavailable")
			var used bool
			require.NoError(t, db.GetDB().QueryRow(`SELECT used FROM mfa_challenges WHERE id='unavailable'`).Scan(&used))
			require.False(t, used)
			for _, table := range []string{"trusted_devices", "idp_sessions", "auth_codes"} {
				var count int
				require.NoError(t, db.GetDB().QueryRow("SELECT count(*) FROM "+table).Scan(&count))
				require.Zero(t, count, table)
			}
			require.Empty(t, rr.Result().Cookies())
		})
	}
}

func TestMfaRevalidatesChangedRegistrationBeforeSideEffects(t *testing.T) {
	for _, policy := range []string{"redirect", "scope", "code grant", "public PKCE"} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			t.Run(policy+"/"+method, func(t *testing.T) {
				atomicEmailChallenge(t)
				// The challenge was valid when created. A later administrative change
				// must be enforced before OTP dispatch, consumption or login issuance.
				if policy == "public PKCE" {
					_, err := db.GetDB().Exec(`UPDATE clients SET client_type='confidential' WHERE client_id='atomic-client'; UPDATE mfa_challenges SET login_state='{"client_id":"atomic-client","redirect_uri":"http://localhost/cb","scope":"openid"}' WHERE id='atomic-challenge'`)
					require.NoError(t, err)
				}
				challenge, err := MfaChallengeByIDIncludingExpired("atomic-challenge")
				require.NoError(t, err)
				_, _, err = challengeClient(challenge)
				require.NoError(t, err, "initial registration is valid")
				changes := map[string]string{"redirect": "redirect_uris='[]'", "scope": "scopes='profile'", "code grant": "grant_types='[]'", "public PKCE": "client_type='public'"}
				_, err = db.GetDB().Exec("UPDATE clients SET " + changes[policy] + " WHERE client_id='atomic-client'")
				require.NoError(t, err)
				var rr *httptest.ResponseRecorder
				if method == http.MethodGet {
					rr = httptest.NewRecorder()
					HandleMfa(rr, httptest.NewRequest(method, "/oauth2/mfa?challenge_id=atomic-challenge", nil))
				} else {
					rr = postAtomicMfa()
				}
				require.Equal(t, http.StatusFound, rr.Code)
				require.Contains(t, rr.Header().Get("Location"), "Verification+client+is+unavailable")
				current, err := MfaChallengeByIDIncludingExpired("atomic-challenge")
				require.NoError(t, err)
				require.False(t, current.Used)
				require.Nil(t, current.OtpSentAt)
				require.Equal(t, challenge.Code, current.Code)
				require.Empty(t, rr.Result().Cookies())
				for _, table := range []string{"auth_codes", "idp_sessions", "trusted_devices"} {
					var count int
					require.NoError(t, db.GetDB().QueryRow("SELECT count(*) FROM "+table).Scan(&count))
					require.Zero(t, count, table)
				}
			})
		}
	}
}
