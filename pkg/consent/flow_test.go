package consent

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

// consentFlowFixture models a client request that reached consent through login.
func consentFlowFixture(t *testing.T) (ConsentParams, string) {
	t.Helper()
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AuthIdpSessionCookieName = testCookieName
		config.Values.RequireMfa = false
		config.Values.AuthSsoEnabled = true
		config.Values.AuthSsoSessionIdleTimeout = time.Hour
		config.Values.AuthSsoSessionMaxAge = 24 * time.Hour
	})
	setupConsentClient(t, "c1")
	sid := createIdpSession(t, "flow-user")
	params := ConsentParams{ClientID: "c1", RedirectURI: "http://localhost/callback", Scope: "openid",
		State: "opaque & state\nvalue", Nonce: "opaque nonce\nvalue", CodeChallenge: "challenge", CodeChallengeMethod: "S256"}
	return withTestConsentFlow(t, sid, params), sid
}

// consentRequest signs only the form, so continuation-tampering tests isolate
// the independent browser/session binding rather than failing at the form MAC.
func consentRequest(method string, params ConsentParams, sid, action string) *http.Request {
	var r *http.Request
	if method == http.MethodGet {
		r = httptest.NewRequest(method, URL(params), nil)
	} else {
		values := params.values()
		values.Set("action", action)
		values.Set("consent_sig", signConsent(params, "flow-user"))
		r = httptest.NewRequest(method, "/oauth2/consent", strings.NewReader(values.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	r.AddCookie(&http.Cookie{Name: testCookieName, Value: sid})
	return r
}

func requireNoConsentGrant(t *testing.T, rr *httptest.ResponseRecorder, status int) {
	t.Helper()
	require.Equal(t, status, rr.Code, rr.Body.String())
	require.NotContains(t, rr.Body.String(), `name="consent_sig"`)
	for _, table := range []string{"auth_codes", "user_consents"} {
		var count int
		require.NoError(t, db.GetDB().QueryRow("SELECT COUNT(*) FROM "+table).Scan(&count))
		require.Zero(t, count, table)
	}
}

func TestConsentGetAndPostRequireOriginalContinuation(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		for _, mutation := range []string{"missing", "state", "nonce", "age", "prompt", "same user different session"} {
			t.Run(method+"/"+mutation, func(t *testing.T) {
				params, sid := consentFlowFixture(t)
				switch mutation {
				case "missing":
					params.FlowToken = ""
				case "state":
					params.State += "tampered"
				case "nonce":
					params.Nonce += "tampered"
				case "age":
					params.MaxAge = "0"
				case "prompt":
					params.Prompt = "login"
				case "same user different session":
					sid = "another-browser"
					require.NoError(t, idpsession.CreateIdpSession(idpsession.IdpSession{ID: sid, UserID: "flow-user"}))
				}
				rr := httptest.NewRecorder()
				HandleConsent(rr, consentRequest(method, params, sid, "allow"))
				requireNoConsentGrant(t, rr, http.StatusUnauthorized)
			})
		}
	}
}

func TestConsentRejectsCurrentRegistrationOnBothMethods(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		for _, mutation := range []string{"scope", "PKCE", "redirect", "inactive", "code grant", "consent disabled"} {
			t.Run(method+"/"+mutation, func(t *testing.T) {
				params, sid := consentFlowFixture(t)
				switch mutation {
				case "scope":
					params.Scope = "openid forbidden"
				case "PKCE":
					params.CodeChallenge, params.CodeChallengeMethod = "", ""
				case "redirect":
					params.RedirectURI = "https://attacker.example/callback"
				default:
					updates := map[string]string{"inactive": "is_active=FALSE", "code grant": "grant_types='[]'", "consent disabled": "consent_required=FALSE"}
					_, err := db.GetDB().Exec("UPDATE clients SET " + updates[mutation] + " WHERE client_id='c1'")
					require.NoError(t, err)
				}
				rr := httptest.NewRecorder()
				HandleConsent(rr, consentRequest(method, params, sid, "allow"))
				requireNoConsentGrant(t, rr, http.StatusBadRequest)
			})
		}
	}
}

func TestConsentSessionAndFlowExpiryOnGetAndApproval(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		for _, limit := range []string{"idle", "absolute", "request max_age", "flow expiry"} {
			t.Run(method+"/"+limit, func(t *testing.T) {
				params, sid := consentFlowFixture(t)
				now := time.Now().UTC()
				created := now.Add(-2 * time.Hour)
				lastActive := now
				issued := now
				switch limit {
				case "idle":
					lastActive = now.Add(-2 * time.Hour)
				case "absolute":
					config.Values.AuthSsoSessionMaxAge = time.Hour
				case "request max_age":
					params.MaxAge = "60"
				case "flow expiry":
					issued = now.Add(-consentFlowLifetime - time.Second)
				}
				_, err := db.GetDB().Exec(`UPDATE idp_sessions SET created_at=?,last_activity_at=? WHERE id=?`, created, lastActive, sid)
				require.NoError(t, err)
				target, err := flowURL(params, sid, flowSSO, issued)
				require.NoError(t, err)
				r := httptest.NewRequest(http.MethodGet, target, nil)
				params = parseConsentParams(r)
				rr := httptest.NewRecorder()
				HandleConsent(rr, consentRequest(method, params, sid, "allow"))
				requireNoConsentGrant(t, rr, http.StatusUnauthorized)
			})
		}
	}
}

func TestConsentDistinguishesActiveLoginFromSso(t *testing.T) {
	for _, kind := range []flowKind{flowLogin, flowSSO} {
		t.Run(string(kind), func(t *testing.T) {
			params, sid := consentFlowFixture(t)
			config.Values.AuthSsoEnabled = false
			params.Prompt, params.MaxAge = "login consent", "0"
			target, err := flowURL(params, sid, kind, time.Now())
			require.NoError(t, err)
			params = parseConsentParams(httptest.NewRequest("GET", target, nil))
			rr := httptest.NewRecorder()
			HandleConsent(rr, consentRequest(http.MethodGet, params, sid, "allow"))
			if kind == flowSSO {
				requireNoConsentGrant(t, rr, http.StatusUnauthorized)
				return
			}
			require.Equal(t, http.StatusOK, rr.Code)
			rr = httptest.NewRecorder()
			HandleConsent(rr, consentRequest(http.MethodPost, params, sid, "allow"))
			require.Equal(t, http.StatusFound, rr.Code, rr.Body.String())
		})
	}
}

func TestConsentCodeRetainsSessionAuthenticationTime(t *testing.T) {
	params, sid := consentFlowFixture(t)
	authenticated := time.Now().UTC().Add(-2 * time.Hour)
	_, err := db.GetDB().Exec(`UPDATE idp_sessions SET created_at=? WHERE id=?`, authenticated, sid)
	require.NoError(t, err)
	rr := httptest.NewRecorder()
	HandleConsent(rr, consentRequest(http.MethodPost, params, sid, "allow"))
	require.Equal(t, http.StatusFound, rr.Code, rr.Body.String())
	var actual time.Time
	require.NoError(t, db.GetDB().QueryRow(`SELECT created_at FROM auth_codes`).Scan(&actual))
	require.True(t, authenticated.Equal(actual), "auth_time cannot become approval time")
}

func TestConsentRequiresExplicitDecision(t *testing.T) {
	params, sid := consentFlowFixture(t)
	rr := httptest.NewRecorder()
	HandleConsent(rr, consentRequest(http.MethodPost, params, sid, ""))
	requireNoConsentGrant(t, rr, http.StatusBadRequest)
}

func TestExplicitConsentWorksForClientThatDoesNotRequireIt(t *testing.T) {
	params, sid := consentFlowFixture(t)
	_, err := db.GetDB().Exec(`UPDATE clients SET consent_required=FALSE WHERE client_id='c1'`)
	require.NoError(t, err)
	params.Prompt = "consent"
	params = withTestConsentFlow(t, sid, params)
	rr := httptest.NewRecorder()
	HandleConsent(rr, consentRequest(http.MethodPost, params, sid, "allow"))
	require.Equal(t, http.StatusFound, rr.Code, rr.Body.String())
	require.True(t, NeedsConsent(nil, "flow-user", "c1", "openid", "consent"))
}
