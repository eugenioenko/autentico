package forwardauth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	"github.com/stretchr/testify/require"
)

func crossSiteApp(t *testing.T, origin string) *App {
	t.Helper()
	a, err := SaveApp("", AppRequest{Name: "Cross-domain app", Origin: origin, AllowedReturnPaths: []string{"/reports"}})
	require.NoError(t, err)
	return a
}

func TestCrossDomainRegistrationUsesExplicitCanonicalOrigins(t *testing.T) {
	fixture(t)
	for input, canonical := range map[string]string{
		"https://dashboard.otherdomain.net":      "https://dashboard.otherdomain.net",
		"https://Dashboard.THIRD.net:443/":       "https://dashboard.third.net",
		"https://reports.fourth.net:8443":        "https://reports.fourth.net:8443",
		"https://xn--bcher-kva.example":          "https://xn--bcher-kva.example",
		"https://auth.example.test.attacker.net": "https://auth.example.test.attacker.net",
	} {
		t.Run(input, func(t *testing.T) {
			a := crossSiteApp(t, input)
			require.Equal(t, canonical, a.Origin)
			require.True(t, a.validStored())
			c, err := client.ClientByClientID(a.ClientID)
			require.NoError(t, err)
			require.Equal(t, []string{canonical + a.route("callback")}, c.GetRedirectURIs())
			require.Equal(t, "public", c.ClientType)
			require.Equal(t, "none", c.TokenEndpointAuthMethod)
			_, err = SaveApp("", AppRequest{Name: "Duplicate", Origin: canonical, AllowedReturnPaths: []string{"/"}})
			require.Error(t, err)
		})
	}
	var before int
	require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM protected_apps`).Scan(&before))
	for _, origin := range []string{
		"http://dashboard.otherdomain.net", "http://dev.localhost", "https://*.otherdomain.net", "//dashboard.otherdomain.net",
		"https://user:password@dashboard.otherdomain.net", "https://dashboard.otherdomain.net/path", "https://dashboard.otherdomain.net?", "https://dashboard.otherdomain.net#",
		"https://dashboard.otherdomain.net:0", "https://dashboard.otherdomain.net:65536", "https://dashboard.otherdomain.net:", "https://dashboard.otherdomain.net./",
		"https://auth.example.test:443", "https://AUTH.EXAMPLE.TEST:8443", "https://otherdomain.net,auth.example.test", "https://otherdomain.net%2fauth.example.test",
	} {
		_, err := SaveApp("", AppRequest{Name: "Invalid", Origin: origin, AllowedReturnPaths: []string{"/"}})
		require.Error(t, err, origin)
	}
	var after int
	require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM protected_apps`).Scan(&after))
	require.Equal(t, before, after)
}

func TestLoopbackOriginExceptionStillRequiresDistinctOrigin(t *testing.T) {
	fixture(t)
	for _, tc := range []struct {
		idp, app string
		allowed  bool
	}{
		{"http://localhost:9999", "http://localhost:8888", true},
		{"http://localhost", "http://LOCALHOST:80/", false},
		{"http://localhost:80", "http://localhost", false},
		{"https://localhost:443", "https://LOCALHOST/", false},
		{"http://127.0.0.1:9999", "http://127.0.0.1:8888", true},
		{"http://[::1]:9999", "http://[::1]:8888", true},
		{"https://auth.example.test", "http://127.0.0.1:8888", true},
		{"https://auth.example.test", "http://192.0.2.1:8888", false},
	} {
		t.Run(tc.idp+"/"+tc.app, func(t *testing.T) {
			config.Bootstrap.AppURL = tc.idp
			r := AppRequest{Name: "Local app", Origin: tc.app, AllowedReturnPaths: []string{"/"}}
			if tc.allowed {
				require.NoError(t, validate(&r))
			} else {
				require.Error(t, validate(&r))
			}
		})
	}
}

func TestCrossSiteCallbackRejectsWrongBrowserOriginAndApplication(t *testing.T) {
	fixture(t)
	a := crossSiteApp(t, "https://dashboard.otherdomain.net")
	b := crossSiteApp(t, "https://reports.third.net")
	c, f, state := start(t, a)
	grant := code(t, a, f)
	target := a.route("callback") + "?code=" + grant + "&state=" + state
	u, err := url.Parse(a.callback())
	require.NoError(t, err)
	require.Equal(t, "dashboard.otherdomain.net", u.Host)
	for _, tc := range []struct {
		name   string
		mutate func(*http.Request)
		status int
	}{
		{"missing browser", func(r *http.Request) { r.Header.Del("Cookie") }, 400},
		{"wrong origin", func(r *http.Request) { r.Header.Set("X-Forwarded-Host", "reports.third.net") }, 403},
		{"wrong scheme", func(r *http.Request) { r.Header.Set("X-Forwarded-Proto", "http") }, 403},
		{"unknown app", func(r *http.Request) { r.SetPathValue("id", "unregistered") }, 403},
		{"crossed app with copied cookie", func(r *http.Request) {
			r.SetPathValue("id", b.ID)
			r.Header.Set("X-Forwarded-Host", "reports.third.net")
		}, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := req(a, target)
			r.AddCookie(c)
			tc.mutate(r)
			w := httptest.NewRecorder()
			HandleCallback(w, r)
			require.Equal(t, tc.status, w.Code)
			require.Empty(t, w.Header().Get("Location"))
			require.Zero(t, count(t))
			stored, err := authcode.AuthCodeByCode(grant)
			require.NoError(t, err)
			require.False(t, stored.Used)
		})
	}
	r := req(a, target)
	r.AddCookie(c)
	w := httptest.NewRecorder()
	HandleCallback(w, r)
	require.Equal(t, 303, w.Code, w.Body.String())
	require.Equal(t, "/reports?q=1", w.Header().Get("Location"))
	require.Equal(t, 1, count(t))
	replay := httptest.NewRecorder()
	HandleCallback(replay, r)
	require.Equal(t, 400, replay.Code)
}

func TestCrossSiteAuthorizationCodeCannotSwitchTransactions(t *testing.T) {
	fixture(t)
	a := crossSiteApp(t, "https://dashboard.otherdomain.net")
	first, firstFlow, firstState := start(t, a)
	second, secondFlow, secondState := start(t, a)
	grant := code(t, a, firstFlow)
	r := req(a, a.route("callback")+"?code="+grant+"&state="+secondState)
	r.AddCookie(second)
	w := httptest.NewRecorder()
	HandleCallback(w, r)
	require.Equal(t, 400, w.Code)
	require.Zero(t, count(t))
	stored, err := authcode.AuthCodeByCode(grant)
	require.NoError(t, err)
	require.False(t, stored.Used)
	for _, tc := range []struct {
		cookie       *http.Cookie
		state, grant string
	}{
		{first, firstState, grant}, {second, secondState, code(t, a, secondFlow)},
	} {
		r := req(a, a.route("callback")+"?code="+tc.grant+"&state="+tc.state)
		r.AddCookie(tc.cookie)
		w := httptest.NewRecorder()
		HandleCallback(w, r)
		require.Equal(t, 303, w.Code)
	}
	require.Equal(t, 2, count(t))
}

func TestCrossSiteSessionSurvivesSafeIdPMoveButRetainsParentRevocation(t *testing.T) {
	fixture(t)
	a := crossSiteApp(t, "https://dashboard.otherdomain.net")
	credential := completeLogin(t, a)
	require.True(t, credential.Secure)
	require.True(t, credential.HttpOnly)
	require.Equal(t, http.SameSiteLaxMode, credential.SameSite)
	require.Empty(t, credential.Domain)
	config.Bootstrap.AppURL = "https://auth.fourth.net"
	require.True(t, a.validStored())
	require.Equal(t, 204, checked(t, a, credential).Code)
	require.NoError(t, idpsession.DeactivateIdpSession("parent"))
	require.Equal(t, 401, checked(t, a, credential).Code)
}
