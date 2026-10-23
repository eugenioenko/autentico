package magiclink

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/trusteddevice"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestMagicLinkClientTrustedDeviceOverride(t *testing.T) {
	for _, allow := range []bool{false, true} {
		t.Run(map[bool]string{false: "deny", true: "allow"}[allow], func(t *testing.T) {
			form, _, _ := newCodeChallenge(t)
			testutils.WithConfigOverride(t, func() {
				config.Values.RequireMfa = true
				config.Values.MfaMethod = "totp"
				config.Values.TrustDeviceEnabled = !allow
			})
			_, err := db.GetDB().Exec(`UPDATE clients SET trust_device_enabled=? WHERE client_id='attempt-client'`, allow)
			require.NoError(t, err)
			require.NoError(t, trusteddevice.CreateTrustedDevice(trusteddevice.TrustedDevice{ID: "trusted", UserID: "attempt-user", ExpiresAt: time.Now().Add(time.Hour)}, "fixture-cookie-token"))
			req := httptest.NewRequest(http.MethodPost, "/oauth2/magic-link/verify", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(&http.Cookie{Name: trusteddevice.CookieName, Value: "fixture-cookie-token"})
			rr := httptest.NewRecorder()
			HandleMagicLinkVerifyCode(rr, req)
			require.Equal(t, http.StatusFound, rr.Code, rr.Body.String())
			if allow {
				require.Contains(t, rr.Header().Get("Location"), "code=")
			} else {
				require.Contains(t, rr.Header().Get("Location"), "/mfa?challenge_id=")
			}
		})
	}
}
