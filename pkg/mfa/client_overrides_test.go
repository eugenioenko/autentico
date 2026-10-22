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
				config.Values.TrustDeviceEnabled = !allow
				config.Values.TrustDeviceExpiration = 30 * 24 * time.Hour
			})
			_, err := db.GetDB().Exec(`UPDATE clients SET trust_device_enabled=?,trust_device_expiration='48h' WHERE client_id='stored-client'; UPDATE clients SET trust_device_enabled=? WHERE client_id='posted-client'`, allow, !allow)
			require.NoError(t, err)
			now := time.Now().UTC()
			require.NoError(t, CreateMfaChallenge(MfaChallenge{ID: "override", UserID: "user-1", Method: "email", Code: utils.HashSHA256("123456"), LoginState: `{"client_id":"stored-client","redirect_uri":"http://localhost/cb","scope":"openid"}`, ExpiresAt: now.Add(time.Hour)}))
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
			_, err = db.GetDB().Exec(`UPDATE clients SET trust_device_expiration='72h' WHERE client_id='stored-client'`)
			require.NoError(t, err)
			form := url.Values{"challenge_id": {"override"}, "code": {"123456"}, "trust_device": {"on"}, "client_id": {"posted-client"}}
			req := httptest.NewRequest(http.MethodPost, "/oauth2/mfa", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()
			HandleMfa(rr, req)
			require.Equal(t, http.StatusFound, rr.Code, rr.Body.String())
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
