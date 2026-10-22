package consent

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestDirectConsentCannotUpgradeSingleFactorSession(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			testutils.WithTestDB(t)
			setupConsentClient(t, "c1")
			sid := createIdpSession(t, "user-1")
			testutils.WithConfigOverride(t, func() {
				config.Bootstrap.AuthIdpSessionCookieName = testCookieName
				config.Values.RequireMfa = true
				config.Values.MfaMethod = "totp"
			})
			params := ConsentParams{ClientID: "c1", RedirectURI: "http://localhost/callback", Scope: "openid", CodeChallenge: "challenge", CodeChallengeMethod: "S256"}
			form := url.Values{"client_id": {params.ClientID}, "redirect_uri": {params.RedirectURI}, "scope": {params.Scope}, "code_challenge": {params.CodeChallenge}, "code_challenge_method": {params.CodeChallengeMethod}, "consent_sig": {signConsent(params, "user-1")}, "action": {"allow"}}
			var r *http.Request
			if method == http.MethodGet {
				r = httptest.NewRequest(method, "/oauth2/consent?"+form.Encode(), nil)
			} else {
				r = httptest.NewRequest(method, "/oauth2/consent", strings.NewReader(form.Encode()))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			r.AddCookie(&http.Cookie{Name: testCookieName, Value: sid})
			rr := httptest.NewRecorder()
			HandleConsent(rr, r)
			require.Equal(t, http.StatusUnauthorized, rr.Code)
			require.Contains(t, rr.Body.String(), "login_required")
			require.NotContains(t, rr.Body.String(), "consent_sig")
			for _, table := range []string{"auth_codes", "user_consents"} {
				var count int
				require.NoError(t, db.GetDB().QueryRow("SELECT COUNT(*) FROM "+table).Scan(&count))
				require.Zero(t, count)
			}
		})
	}
}
