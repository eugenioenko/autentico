package authorize

import (
	"encoding/json"
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

func TestUnsupportedResponseTypesCannotAcquireCodesFromLegacyRegistrations(t *testing.T) {
	for _, responseType := range []string{"token", "id_token", "code token", "unknown"} {
		for _, hasSession := range []bool{false, true} {
			label := responseType + "/anonymous"
			if hasSession {
				label = responseType + "/SSO"
			}
			t.Run(label, func(t *testing.T) {
				testutils.WithTestDB(t)
				testutils.InsertTestClient(t, "legacy", []string{"http://localhost/cb?registered=kept"})
				testutils.InsertTestUser(t, "response-user")
				testutils.WithConfigOverride(t, func() {
					config.Values.AuthSsoEnabled = true
					config.Values.RequireMfa = false
					config.Values.AuthSsoSessionIdleTimeout = 0
					config.Values.AuthSsoSessionMaxAge = 0
					config.Bootstrap.AuthIdpSessionCookieName = "idp"
				})
				types, err := json.Marshal([]string{"code", responseType})
				require.NoError(t, err)
				_, err = db.GetDB().Exec(`UPDATE clients SET response_types=? WHERE client_id='legacy'`, string(types))
				require.NoError(t, err)
				if hasSession {
					require.NoError(t, idpsession.CreateIdpSession(idpsession.IdpSession{ID: "response-login", UserID: "response-user"}))
				}
				values := url.Values{"client_id": {"legacy"}, "redirect_uri": {"http://localhost/cb?registered=kept"}, "scope": {"openid"},
					"response_type": {responseType}, "state": {"opaque & state"}, "code_challenge": {"challenge"}, "code_challenge_method": {"S256"}}
				for _, method := range []string{http.MethodGet, http.MethodPost} {
					r := httptest.NewRequest(method, "/oauth2/authorize?"+values.Encode(), nil)
					if method == http.MethodPost {
						r = httptest.NewRequest(method, "/oauth2/authorize", strings.NewReader(values.Encode()))
						r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					}
					if hasSession {
						r.AddCookie(&http.Cookie{Name: "idp", Value: "response-login"})
					}
					rr := httptest.NewRecorder()
					HandleAuthorize(rr, r)
					require.Equal(t, http.StatusFound, rr.Code, rr.Body.String())
					target, err := url.Parse(rr.Header().Get("Location"))
					require.NoError(t, err)
					require.Equal(t, "http", target.Scheme)
					require.Equal(t, "localhost", target.Host)
					require.Equal(t, "/cb", target.Path)
					require.Equal(t, "unsupported_response_type", target.Query().Get("error"))
					require.Equal(t, "opaque & state", target.Query().Get("state"))
					require.Equal(t, "kept", target.Query().Get("registered"))
					require.Empty(t, target.Query().Get("code"))
				}
				var count int
				require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM auth_codes`).Scan(&count))
				require.Zero(t, count)
			})
		}
	}
}

func TestSsoCannotIssueCodesOutsideTheRegisteredGrantTypes(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "service-only", []string{"http://localhost/cb"})
	testutils.InsertTestUser(t, "grant-user")
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthSsoEnabled = true
		config.Values.RequireMfa = false
		config.Bootstrap.AuthIdpSessionCookieName = "idp"
	})
	_, err := db.GetDB().Exec(`UPDATE clients SET grant_types='["client_credentials"]', response_types='["code"]' WHERE client_id='service-only'`)
	require.NoError(t, err)
	require.NoError(t, idpsession.CreateIdpSession(idpsession.IdpSession{ID: "grant-login", UserID: "grant-user"}))
	form := url.Values{"client_id": {"service-only"}, "redirect_uri": {"http://localhost/cb"}, "scope": {"openid"},
		"response_type": {"code"}, "state": {"grant-state"}, "code_challenge": {"challenge"}, "code_challenge_method": {"S256"}}
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		r := httptest.NewRequest(method, "/oauth2/authorize?"+form.Encode(), nil)
		if method == http.MethodPost {
			r = httptest.NewRequest(method, "/oauth2/authorize", strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		r.AddCookie(&http.Cookie{Name: "idp", Value: "grant-login"})
		rr := httptest.NewRecorder()
		HandleAuthorize(rr, r)
		require.Equal(t, http.StatusFound, rr.Code)
		target, err := url.Parse(rr.Header().Get("Location"))
		require.NoError(t, err)
		require.Equal(t, "unauthorized_client", target.Query().Get("error"))
		require.Empty(t, target.Query().Get("code"))
	}
	var count int
	require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM auth_codes`).Scan(&count))
	require.Zero(t, count)
}
