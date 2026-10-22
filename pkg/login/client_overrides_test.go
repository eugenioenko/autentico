package login

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
	"github.com/eugenioenko/autentico/pkg/user"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestLoginClientTrustedDeviceOverride(t *testing.T) {
	for _, allow := range []bool{false, true} {
		t.Run(map[bool]string{false: "deny", true: "allow"}[allow], func(t *testing.T) {
			testutils.WithTestDB(t)
			testutils.InsertTestClient(t, "override", []string{"http://localhost/cb"})
			testutils.WithConfigOverride(t, func() {
				config.Values.RequireMfa = true
				config.Values.MfaMethod = "totp"
				config.Values.TrustDeviceEnabled = !allow
			})
			usr, err := user.CreateUser("override-user", "Password123!", "override@example.com")
			require.NoError(t, err)
			_, err = db.GetDB().Exec(`UPDATE clients SET trust_device_enabled=? WHERE client_id='override'`, allow)
			require.NoError(t, err)
			require.NoError(t, trusteddevice.CreateTrustedDevice(trusteddevice.TrustedDevice{ID: "trusted", UserID: usr.ID, ExpiresAt: time.Now().Add(time.Hour)}))
			form := url.Values{"client_id": {"override"}, "redirect_uri": {"http://localhost/cb"}, "username": {"override-user"}, "password": {"Password123!"}}
			testutils.SetAuthorizeSig(form)
			req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(&http.Cookie{Name: trusteddevice.CookieName, Value: "trusted"})
			rr := httptest.NewRecorder()
			HandleLoginUser(rr, req)
			require.Equal(t, http.StatusFound, rr.Code)
			if allow {
				require.Contains(t, rr.Header().Get("Location"), "code=")
			} else {
				require.Contains(t, rr.Header().Get("Location"), "/mfa?challenge_id=")
			}
		})
	}
}
