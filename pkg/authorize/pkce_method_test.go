package authorize

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestAuthorizeRejectsInvalidPKCEMethodBeforeLoginOrSSO(t *testing.T) {
	for _, clientType := range []string{"public", "confidential"} {
		for _, tc := range []struct{ challenge, method string }{{"challenge", "S512"}, {"challenge", "s256"}, {"", "S256"}, {"", "plain"}} {
			for _, hasSession := range []bool{false, true} {
				for _, method := range []string{http.MethodGet, http.MethodPost} {
					t.Run(fmt.Sprintf("%s/%s/%s/session=%t/%s", clientType, tc.challenge, tc.method, hasSession, method), func(t *testing.T) {
						testutils.WithTestDB(t)
						testutils.InsertTestClient(t, "pkce-client", []string{"http://localhost/cb?registered=kept"})
						testutils.InsertTestUser(t, "pkce-user")
						testutils.WithConfigOverride(t, func() {
							config.Values.AuthSsoEnabled = true
							config.Values.RequireMfa = false
							config.Values.AuthSsoSessionIdleTimeout = 0
							config.Values.AuthSsoSessionMaxAge = 0
							config.Values.AuthPKCEEnforceSHA256 = false
							config.Bootstrap.AuthIdpSessionCookieName = "idp"
						})
						_, err := db.GetDB().Exec(`UPDATE clients SET client_type=? WHERE client_id='pkce-client'`, clientType)
						require.NoError(t, err)
						if hasSession {
							require.NoError(t, idpsession.CreateIdpSession(idpsession.IdpSession{ID: "pkce-session", UserID: "pkce-user"}))
						}
						values := url.Values{"client_id": {"pkce-client"}, "redirect_uri": {"http://localhost/cb?registered=kept"}, "scope": {"openid"}, "response_type": {"code"}, "state": {"opaque & state"}, "code_challenge": {tc.challenge}, "code_challenge_method": {tc.method}}
						r := httptest.NewRequest(method, "/oauth2/authorize?"+values.Encode(), nil)
						if method == http.MethodPost {
							r = httptest.NewRequest(method, "/oauth2/authorize", strings.NewReader(values.Encode()))
							r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
						}
						if hasSession {
							r.AddCookie(&http.Cookie{Name: "idp", Value: "pkce-session"})
						}
						rr := httptest.NewRecorder()
						HandleAuthorize(rr, r)
						require.Equal(t, http.StatusFound, rr.Code, rr.Body.String())
						target, err := url.Parse(rr.Header().Get("Location"))
						require.NoError(t, err)
						require.Equal(t, "http://localhost/cb", target.Scheme+"://"+target.Host+target.Path)
						require.Equal(t, "invalid_request", target.Query().Get("error"))
						require.Equal(t, "opaque & state", target.Query().Get("state"))
						require.Equal(t, "kept", target.Query().Get("registered"))
						require.Empty(t, target.Query().Get("code"))
						var count int
						require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM auth_codes`).Scan(&count))
						require.Zero(t, count)
					})
				}
			}
		}
	}
}
