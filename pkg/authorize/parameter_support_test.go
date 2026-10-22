package authorize

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestAuthorizeParameterSupportBeforeLoginAndSSO(t *testing.T) {
	var fetched atomic.Int32
	requestObject := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fetched.Add(1); w.WriteHeader(http.StatusOK) }))
	defer requestObject.Close()
	for _, tc := range []struct{ name, extra, errorCode string }{
		{"request URI", "request_uri=" + url.QueryEscape(requestObject.URL+"/request.jwt"), "request_uri_not_supported"},
		{"opaque request URI", "request_uri=not-a-uri", "request_uri_not_supported"},
		{"empty request URI", "request_uri=", ""},
		{"bare request URI", "request_uri", ""},
		{"absent parameters", "", ""},
	} {
		for _, hasSession := range []bool{false, true} {
			for _, method := range []string{http.MethodGet, http.MethodPost} {
				t.Run(fmt.Sprintf("%s/session=%t/%s", tc.name, hasSession, method), func(t *testing.T) {
					testutils.WithTestDB(t)
					testutils.InsertTestClient(t, "parameter-client", []string{"http://localhost/cb?registered=kept"})
					testutils.InsertTestUser(t, "parameter-user")
					testutils.WithConfigOverride(t, func() {
						config.Values.AuthSsoEnabled = true
						config.Values.RequireMfa = false
						config.Values.AuthSsoSessionIdleTimeout = 0
						config.Values.AuthSsoSessionMaxAge = 0
						config.Values.AuthPKCEEnforceSHA256 = true
						config.Bootstrap.AuthIdpSessionCookieName = "idp"
					})
					if hasSession {
						require.NoError(t, idpsession.CreateIdpSession(idpsession.IdpSession{ID: "parameter-session", UserID: "parameter-user"}))
					}
					values := url.Values{"client_id": {"parameter-client"}, "redirect_uri": {"http://localhost/cb?registered=kept"}, "scope": {"openid"}, "response_type": {"code"}, "state": {"opaque & state"}, "code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}, "code_challenge_method": {"S256"}}
					wire := values.Encode() + "&" + tc.extra
					r := httptest.NewRequest(method, "/oauth2/authorize?"+wire, nil)
					if method == http.MethodPost {
						r = httptest.NewRequest(method, "/oauth2/authorize", strings.NewReader(wire))
						r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					}
					if hasSession {
						r.AddCookie(&http.Cookie{Name: "idp", Value: "parameter-session"})
					}
					rr := httptest.NewRecorder()
					HandleAuthorize(rr, r)
					target, err := url.Parse(rr.Header().Get("Location"))
					require.NoError(t, err)
					if tc.errorCode != "" || hasSession {
						require.Equal(t, http.StatusFound, rr.Code, rr.Body.String())
						require.Equal(t, "http://localhost/cb", target.Scheme+"://"+target.Host+target.Path)
						require.Equal(t, "kept", target.Query().Get("registered"))
						require.Equal(t, "opaque & state", target.Query().Get("state"))
						require.Equal(t, tc.errorCode, target.Query().Get("error"))
						if tc.errorCode == "" {
							require.NotEmpty(t, target.Query().Get("code"))
						} else {
							require.Empty(t, target.Query().Get("code"))
						}
					} else if method == http.MethodPost {
						require.Equal(t, http.StatusFound, rr.Code)
						require.Equal(t, "/oauth2/authorize", target.Path)
						require.Empty(t, target.Query().Get("error"))
					} else {
						require.Equal(t, http.StatusOK, rr.Code)
					}
					var count int
					require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM auth_codes`).Scan(&count))
					if tc.errorCode == "" && hasSession {
						require.Equal(t, 1, count)
					} else {
						require.Zero(t, count)
					}
					require.Zero(t, fetched.Load(), "unsupported request objects must never be fetched")
				})
			}
		}
	}
}
