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

func TestAuthorizeOmittedPKCEMethodMeansPlain(t *testing.T) {
	for _, clientType := range []string{"public", "confidential"} {
		for _, enforce := range []bool{true, false} {
			for _, hasSession := range []bool{true, false} {
				for _, method := range []string{http.MethodGet, http.MethodPost} {
					t.Run(fmt.Sprintf("%s/enforce=%t/session=%t/%s", clientType, enforce, hasSession, method), func(t *testing.T) {
						testutils.WithTestDB(t)
						testutils.InsertTestClient(t, "default-client", []string{"http://localhost/cb"})
						testutils.InsertTestUser(t, "default-user")
						testutils.WithConfigOverride(t, func() {
							config.Values.AuthPKCEEnforceSHA256 = enforce
							config.Values.AuthSsoEnabled = true
							config.Values.RequireMfa = false
							config.Values.AuthSsoSessionIdleTimeout = 0
							config.Values.AuthSsoSessionMaxAge = 0
							config.Bootstrap.AuthIdpSessionCookieName = "idp"
						})
						_, err := db.GetDB().Exec(`UPDATE clients SET client_type=? WHERE client_id='default-client'`, clientType)
						require.NoError(t, err)
						if hasSession {
							require.NoError(t, idpsession.CreateIdpSession(idpsession.IdpSession{ID: "default-session", UserID: "default-user"}))
						}
						values := url.Values{"client_id": {"default-client"}, "redirect_uri": {"http://localhost/cb"}, "scope": {"openid"}, "response_type": {"code"}, "state": {"default-state"}, "code_challenge": {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"}}
						r := httptest.NewRequest(method, "/oauth2/authorize?"+values.Encode(), nil)
						if method == http.MethodPost {
							r = httptest.NewRequest(method, "/oauth2/authorize", strings.NewReader(values.Encode()))
							r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
						}
						if hasSession {
							r.AddCookie(&http.Cookie{Name: "idp", Value: "default-session"})
						}
						rr := httptest.NewRecorder()
						HandleAuthorize(rr, r)
						target, err := url.Parse(rr.Header().Get("Location"))
						require.NoError(t, err)
						if enforce {
							require.Equal(t, http.StatusFound, rr.Code)
							require.Equal(t, "http://localhost/cb", target.Scheme+"://"+target.Host+target.Path)
							require.Equal(t, "invalid_request", target.Query().Get("error"))
							require.Equal(t, "default-state", target.Query().Get("state"))
							require.Empty(t, target.Query().Get("code"))
						} else if hasSession {
							require.Equal(t, http.StatusFound, rr.Code)
							require.Empty(t, target.Query().Get("error"))
							require.NotEmpty(t, target.Query().Get("code"))
							var stored string
							require.NoError(t, db.GetDB().QueryRow(`SELECT code_challenge_method FROM auth_codes WHERE code=?`, target.Query().Get("code")).Scan(&stored))
							require.Equal(t, "plain", stored)
						} else if method == http.MethodPost {
							require.Equal(t, http.StatusFound, rr.Code)
							require.Equal(t, "/oauth2/authorize", target.Path)
							require.Equal(t, "plain", target.Query().Get("code_challenge_method"))
						} else {
							require.Equal(t, http.StatusOK, rr.Code)
							require.Contains(t, rr.Body.String(), `name="code_challenge_method" value="plain"`)
						}
						var count int
						require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM auth_codes`).Scan(&count))
						if !enforce && hasSession {
							require.Equal(t, 1, count)
						} else {
							require.Zero(t, count)
						}
					})
				}
			}
		}
	}
}
