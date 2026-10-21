package authorize

import (
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

func TestAuthorizeSsoAndErrorPreserveExistingQueryAndOpaqueState(t *testing.T) {
	for _, withSession := range []bool{false, true} {
		t.Run(map[bool]string{false: "error", true: "SSO"}[withSession], func(t *testing.T) {
			testutils.WithTestDB(t)
			testutils.WithConfigOverride(t, func() {
				config.Values.AuthSsoEnabled = true
				config.Values.AuthSsoSessionIdleTimeout = 0
				config.Values.AuthSsoSessionMaxAge = 0
				config.Bootstrap.AuthIdpSessionCookieName = "query-idp"
			})
			callback := "http://localhost/callback?existing=a%26b&repeat=1&repeat=2"
			state := "state & injected=1 + %25 # é"
			testutils.InsertTestClient(t, "query-client", []string{callback})
			query := url.Values{"response_type": {"code"}, "client_id": {"query-client"}, "redirect_uri": {callback}, "scope": {"openid"}, "state": {state},
				"prompt": {"none"}, "code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}, "code_challenge_method": {"S256"}}
			req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+query.Encode(), nil)
			if withSession {
				testutils.InsertTestUser(t, "query-user")
				require.NoError(t, idpsession.CreateIdpSession(idpsession.IdpSession{ID: "query-idp", UserID: "query-user", UserAgent: "test", IPAddress: "127.0.0.1"}))
				req.AddCookie(&http.Cookie{Name: "query-idp", Value: "query-idp"})
			}
			rr := httptest.NewRecorder()
			HandleAuthorize(rr, req)
			require.Equal(t, http.StatusFound, rr.Code)
			target, err := url.Parse(rr.Header().Get("Location"))
			require.NoError(t, err)
			require.Empty(t, target.Fragment)
			response := target.Query()
			require.Equal(t, []string{"a&b"}, response["existing"])
			require.Equal(t, []string{"1", "2"}, response["repeat"])
			require.Equal(t, []string{state}, response["state"])
			require.NotContains(t, response, "injected")
			if withSession {
				require.Len(t, response["code"], 1)
				var redirect string
				require.NoError(t, db.GetDB().QueryRow("SELECT redirect_uri FROM auth_codes WHERE code=?", response.Get("code")).Scan(&redirect))
				require.Equal(t, callback, redirect)
			} else {
				require.Equal(t, "login_required", response.Get("error"))
				require.NotContains(t, response, "code")
			}
		})
	}
}
