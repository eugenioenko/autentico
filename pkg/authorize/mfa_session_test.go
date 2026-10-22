package authorize

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestSsoRequiresCurrentMfaEvidence(t *testing.T) {
	for _, tt := range []struct {
		evidence string
		consent  bool
	}{
		{"", false}, {"", true}, {"email", false}, {"email", true},
		{"totp", false}, {"trusted_device", false},
	} {
		t.Run(fmt.Sprintf("evidence=%s/consent=%t", tt.evidence, tt.consent), func(t *testing.T) {
			testutils.WithTestDB(t)
			testutils.InsertTestUser(t, "user-1")
			testutils.InsertTestClient(t, "c1", []string{"http://localhost/cb"})
			testutils.WithConfigOverride(t, func() {
				config.Values.RequireMfa = true
				config.Values.MfaMethod = "totp"
				config.Values.AuthSsoEnabled = true
				config.Values.AuthSsoSessionMaxAge = 0
				config.Values.AuthSsoSessionIdleTimeout = 0
				config.Bootstrap.AuthIdpSessionCookieName = "idp"
			})
			_, err := db.GetDB().Exec(`UPDATE users SET totp_verified=TRUE WHERE id='user-1'`)
			require.NoError(t, err)
			_, err = db.GetDB().Exec(`UPDATE clients SET consent_required=? WHERE client_id='c1'`, tt.consent)
			require.NoError(t, err)
			require.NoError(t, idpsession.CreateIdpSession(idpsession.IdpSession{ID: "sso", UserID: "user-1", MfaMethod: tt.evidence}))
			q := url.Values{"client_id": {"c1"}, "redirect_uri": {"http://localhost/cb"}, "response_type": {"code"}, "code_challenge": {"challenge"}, "code_challenge_method": {"S256"}, "prompt": {"none"}}
			r := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil)
			r.AddCookie(&http.Cookie{Name: "idp", Value: "sso"})
			rr := httptest.NewRecorder()
			HandleAuthorize(rr, r)
			target, err := url.Parse(rr.Header().Get("Location"))
			require.NoError(t, err)
			if tt.evidence == "totp" || tt.evidence == "trusted_device" {
				require.NotEmpty(t, target.Query().Get("code"))
				require.Empty(t, target.Query().Get("error"))
			} else {
				require.Equal(t, "login_required", target.Query().Get("error"))
				var count int
				require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM auth_codes`).Scan(&count))
				require.Zero(t, count)
			}
		})
	}
}
