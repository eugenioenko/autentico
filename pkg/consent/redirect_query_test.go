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

func TestConsentRedirectPreservesExistingQueryAndOpaqueState(t *testing.T) {
	for _, action := range []string{"allow", "deny"} {
		t.Run(action, func(t *testing.T) {
			testutils.WithTestDB(t)
			testutils.WithConfigOverride(t, func() { config.Bootstrap.AuthIdpSessionCookieName = testCookieName })
			callback := "http://localhost/callback?existing=a%26b&repeat=1&repeat=2"
			state := "state & injected=1 + %25 # é"
			testutils.InsertTestClient(t, "query-client", []string{callback})
			sessionID := createIdpSession(t, "query-user")
			params := ConsentParams{ClientID: "query-client", RedirectURI: callback, Scope: "openid", State: state,
				CodeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", CodeChallengeMethod: "S256"}
			form := url.Values{"action": {action}, "client_id": {params.ClientID}, "redirect_uri": {callback}, "scope": {params.Scope}, "state": {state},
				"code_challenge": {params.CodeChallenge}, "code_challenge_method": {params.CodeChallengeMethod}, "consent_sig": {signConsent(params, "query-user")}}
			req := httptest.NewRequest(http.MethodPost, "/oauth2/consent", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(&http.Cookie{Name: testCookieName, Value: sessionID})
			rr := httptest.NewRecorder()
			HandleConsent(rr, req)
			require.Equal(t, http.StatusFound, rr.Code)
			target, err := url.Parse(rr.Header().Get("Location"))
			require.NoError(t, err)
			require.Empty(t, target.Fragment)
			query := target.Query()
			require.Equal(t, []string{"a&b"}, query["existing"])
			require.Equal(t, []string{"1", "2"}, query["repeat"])
			require.Equal(t, []string{state}, query["state"])
			require.NotContains(t, query, "injected")
			if action == "allow" {
				require.Len(t, query["code"], 1)
				var redirect string
				require.NoError(t, db.GetDB().QueryRow("SELECT redirect_uri FROM auth_codes WHERE code=?", query.Get("code")).Scan(&redirect))
				require.Equal(t, callback, redirect)
			} else {
				require.Equal(t, "access_denied", query.Get("error"))
				require.NotContains(t, query, "code")
			}
		})
	}
}
