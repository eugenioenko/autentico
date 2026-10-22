package emailverification

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/user"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestEmailVerificationRequiresLocalTotpAndConsent(t *testing.T) {
	for _, tt := range []struct {
		name               string
		required, enrolled bool
	}{
		{"required enrollment", true, false},
		{"voluntary TOTP", false, true},
		{"consent without MFA", false, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			withVerificationTestDB(t)
			testutils.WithConfigOverride(t, func() {
				config.Values.RequireMfa = tt.required
				config.Values.MfaMethod = "totp"
				config.Values.TrustDeviceEnabled = false
			})
			usr, err := user.CreateUser("local", "Password123!", "local@example.com")
			require.NoError(t, err)
			_, err = db.GetDB().Exec(`UPDATE users SET totp_verified=? WHERE id=?`, tt.enrolled, usr.ID)
			require.NoError(t, err)
			_, err = db.GetDB().Exec(`UPDATE clients SET consent_required=TRUE WHERE client_id='test-client'`)
			require.NoError(t, err)
			raw, hash, err := GenerateToken()
			require.NoError(t, err)
			require.NoError(t, user.SetEmailVerificationToken(usr.ID, hash, time.Now().Add(time.Minute)))
			q := url.Values{"token": {raw}, "scope": {"openid"}}
			signVerificationParams(q)
			rr := httptest.NewRecorder()
			HandleVerifyEmail(rr, httptest.NewRequest(http.MethodGet, "/oauth2/verify-email?"+q.Encode(), nil))
			require.Equal(t, http.StatusFound, rr.Code)
			target, err := url.Parse(rr.Header().Get("Location"))
			require.NoError(t, err)
			if tt.required || tt.enrolled {
				require.Equal(t, "/oauth2/mfa", target.Path)
				require.Empty(t, rr.Result().Cookies())
			} else {
				require.Equal(t, "/oauth2/consent", target.Path)
			}
			var count int
			require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM auth_codes`).Scan(&count))
			require.Zero(t, count)
			loaded, err := user.UserByID(usr.ID)
			require.NoError(t, err)
			require.True(t, loaded.IsEmailVerified)
		})
	}
}
