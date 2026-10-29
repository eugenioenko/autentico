package forwardauth

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func fixture(t *testing.T) *App {
	t.Helper()
	prevBS, prevConfig := config.Bootstrap, config.Values
	t.Cleanup(func() { config.Bootstrap = prevBS; config.Values = prevConfig })
	config.Bootstrap.AppURL = "https://auth.example.test"
	config.Bootstrap.AppOAuthPath = "/oauth2"
	config.Bootstrap.AuthCSRFProtectionSecretKey = strings.Repeat("test-key", 8)
	config.Bootstrap.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	config.Values.RequireMfa = false
	config.Values.AuthSsoSessionIdleTimeout = time.Hour
	config.Values.AuthSsoSessionMaxAge = 24 * time.Hour
	config.Values.RequireEmailVerification = false
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user")
	a, err := SaveApp("", AppRequest{Name: "Dashboard", Origin: "https://app.example.test", AllowedReturnPaths: []string{"/reports"}, SessionTTL: "1h"})
	require.NoError(t, err)
	require.NoError(t, idpsession.CreateIdpSession(idpsession.IdpSession{ID: "parent", UserID: "user"}))
	return a
}

func req(a *App, route string) *http.Request {
	r := httptest.NewRequest("GET", route, nil)
	r.RemoteAddr = "127.0.0.1:1234"
	r.SetPathValue("id", a.ID)
	r.Header.Set("X-Forwarded-Host", "app.example.test")
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Uri", "/reports?q=1")
	r.Header.Set("X-Forwarded-Method", "GET")
	return r
}

func start(t *testing.T, a *App) (*http.Cookie, loginFlow, string) {
	t.Helper()
	w := httptest.NewRecorder()
	HandleStart(w, req(a, a.route("start")+"?return=%2Freports%3Fq%3D1"))
	require.Equal(t, 303, w.Code, w.Body.String())
	location, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	c := w.Result().Cookies()[0]
	sc, err := codec()
	require.NoError(t, err)
	var flow loginFlow
	require.NoError(t, sc.Decode(c.Name, c.Value, &flow))
	return c, flow, location.Query().Get("state")
}
func code(t *testing.T, a *App, f loginFlow) string {
	t.Helper()
	value, err := authcode.GenerateSecureCode()
	require.NoError(t, err)
	challenge := sha256.Sum256([]byte(f.Verifier))
	require.NoError(t, authcode.CreateAuthCode(authcode.AuthCode{Code: value, UserID: "user", ClientID: a.ClientID, RedirectURI: a.callback(), Scope: "openid", Nonce: f.Nonce, CodeChallenge: base64.RawURLEncoding.EncodeToString(challenge[:]), CodeChallengeMethod: "S256", ExpiresAt: time.Now().UTC().Add(time.Minute), IdpSessionID: "parent"}))
	return value
}
func count(t *testing.T) int {
	t.Helper()
	var n int
	require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM forward_auth_sessions`).Scan(&n))
	return n
}

func TestReturnPathAllowlist(t *testing.T) {
	a := App{AllowedReturnPaths: []string{"/reports"}}
	for _, p := range []string{"/reports", "/reports/2026?q=10", "/reports?q=%26x%3D1", "/reports?q=a;b"} {
		require.True(t, a.allowReturn(p), p)
	}
	for _, p := range []string{"", "https://evil.test/reports", "//evil.test/reports", "/reports-other", "/reports/../admin", "/reports/%2e%2e/admin", "/reports/%252e%252e/admin", "/reports/%5cevil", "/reports//evil", "/reports#fragment", "/reports/%00", "/reports/..;/admin", "/reports/%2e%2e%3b/admin", "/reports/a;parameter/admin", "/_autentico/start"} {
		require.False(t, a.allowReturn(p), p)
	}
}
func TestRegistrationValidationAndRejectedUpdates(t *testing.T) {
	a := fixture(t)
	for _, origin := range []string{"http://app.example.test", "https://app.other.test", "https://auth.example.test", "https://auth.example.test:8443", "https://user@app.example.test", "https://app.example.test/path", "https://app.example.test?x=1", "https://app.example.test#", "https://example.test.evil.test"} {
		_, err := SaveApp("", AppRequest{Name: "bad", Origin: origin, AllowedReturnPaths: []string{"/"}})
		require.Error(t, err, origin)
	}
	_, err := SaveApp(a.ID, AppRequest{Name: "changed", Origin: "https://other.example.test", AllowedReturnPaths: []string{"/"}})
	require.Error(t, err)
	stored, err := AppByID(a.ID)
	require.NoError(t, err)
	require.Equal(t, *a, *stored)
	var n int
	require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM clients WHERE client_id LIKE 'forward-auth-%'`).Scan(&n))
	require.Equal(t, 1, n)
}
func TestProxyTrustAndAmbiguousHeaders(t *testing.T) {
	a := fixture(t)
	for _, change := range []func(*http.Request){
		func(r *http.Request) { r.RemoteAddr = "192.0.2.1:1234" },
		func(r *http.Request) { r.Header.Set("X-Forwarded-Host", "evil.example.test") },
		func(r *http.Request) { r.Header.Add("X-Forwarded-Host", "app.example.test") },
		func(r *http.Request) { r.Header.Set("X-Forwarded-Proto", "http") },
		func(r *http.Request) { r.Header.Set("X-Forwarded-Method", "") },
		func(r *http.Request) { r.Header.Set("X-Forwarded-Uri", "//evil.test") },
	} {
		r := req(a, "/check")
		change(r)
		w := httptest.NewRecorder()
		HandleCheck(w, r)
		require.Equal(t, 403, w.Code)
	}
	for _, method := range []string{"GET", "POST"} {
		r := req(a, "/check?redirect=1")
		r.Header.Set("X-Forwarded-Method", method)
		r.Header.Set("Accept", "text/html")
		w := httptest.NewRecorder()
		HandleCheck(w, r)
		if method == "GET" {
			require.Equal(t, 303, w.Code)
		} else {
			require.Equal(t, 401, w.Code)
			require.Empty(t, w.Header().Get("Location"))
		}
		require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	}
}
func TestCallbackBrowserBindingReplayAndCredentialIsolation(t *testing.T) {
	a := fixture(t)
	c, f, state := start(t, a)
	grant := code(t, a, f)
	target := a.route("callback") + "?code=" + grant + "&state=" + state
	wrong := httptest.NewRecorder()
	HandleCallback(wrong, req(a, target))
	require.Equal(t, 400, wrong.Code)
	require.Equal(t, 0, count(t))
	unused, err := authcode.AuthCodeByCode(grant)
	require.NoError(t, err)
	require.False(t, unused.Used)
	r := req(a, target)
	r.AddCookie(c)
	w := httptest.NewRecorder()
	HandleCallback(w, r)
	require.Equal(t, 303, w.Code, w.Body.String())
	require.Equal(t, "/reports?q=1", w.Header().Get("Location"))
	require.Equal(t, 1, count(t))
	var session *http.Cookie
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == a.cookieName() {
			session = cookie
		}
	}
	require.NotNil(t, session)
	require.True(t, session.Secure)
	require.True(t, session.HttpOnly)
	require.Empty(t, session.Domain)
	require.Equal(t, http.SameSiteLaxMode, session.SameSite)
	var stored string
	require.NoError(t, db.GetDB().QueryRow(`SELECT token_hash FROM forward_auth_sessions`).Scan(&stored))
	require.Equal(t, hash(session.Value), stored)
	require.NotEqual(t, session.Value, stored)
	check := req(a, "/check")
	check.AddCookie(session)
	check.AddCookie(c)
	check.AddCookie(&http.Cookie{Name: "app-preference", Value: "dark"})
	check.Header.Set("X-Auth-User", "forged")
	good := httptest.NewRecorder()
	HandleCheck(good, check)
	require.Equal(t, 204, good.Code)
	require.Equal(t, "user", good.Header().Get("X-Auth-User"))
	require.Equal(t, "app-preference=dark", good.Header().Get("Cookie"))
	replay := httptest.NewRecorder()
	HandleCallback(replay, r)
	require.Equal(t, 400, replay.Code)
	require.Equal(t, 1, count(t))
	require.NoError(t, idpsession.DeactivateWithCascade("parent"))
	denied := httptest.NewRecorder()
	HandleCheck(denied, check)
	require.Equal(t, 401, denied.Code)
}
func TestCallbackRejectsInvalidBindingsWithoutMutation(t *testing.T) {
	for _, field := range []string{"nonce", "challenge", "expired", "client", "parent", "cookie", "state", "expired-flow", "client-policy"} {
		t.Run(field, func(t *testing.T) {
			a := fixture(t)
			c, f, state := start(t, a)
			grant := code(t, a, f)
			switch field {
			case "nonce":
				_, err := db.GetDB().Exec(`UPDATE auth_codes SET nonce='different' WHERE code=?`, grant)
				require.NoError(t, err)
			case "challenge":
				_, err := db.GetDB().Exec(`UPDATE auth_codes SET code_challenge='different' WHERE code=?`, grant)
				require.NoError(t, err)
			case "expired":
				_, err := db.GetDB().Exec(`UPDATE auth_codes SET expires_at=? WHERE code=?`, time.Now().Add(-time.Minute), grant)
				require.NoError(t, err)
			case "client":
				_, err := db.GetDB().Exec(`UPDATE auth_codes SET client_id='other' WHERE code=?`, grant)
				require.NoError(t, err)
			case "parent":
				require.NoError(t, idpsession.DeactivateWithCascade("parent"))
			case "cookie":
				c.Value += "tamper"
			case "state":
				state = strings.Repeat("a", 43)
			case "expired-flow":
				f.ExpiresAt = time.Now().Add(-time.Second).Unix()
				sc, err := codec()
				require.NoError(t, err)
				c.Value, err = sc.Encode(c.Name, f)
				require.NoError(t, err)
			case "client-policy":
				_, err := db.GetDB().Exec(`UPDATE clients SET grant_types='[]' WHERE client_id=?`, a.ClientID)
				require.NoError(t, err)
			}
			r := req(a, a.route("callback")+"?code="+grant+"&state="+state)
			r.AddCookie(c)
			w := httptest.NewRecorder()
			HandleCallback(w, r)
			require.GreaterOrEqual(t, w.Code, 400, w.Body.String())
			require.Equal(t, 0, count(t))
		})
	}
}
func TestConcurrentRedemptionSingleSession(t *testing.T) {
	a := fixture(t)
	c, f, state := start(t, a)
	grant := code(t, a, f)
	var wg sync.WaitGroup
	results := make(chan int, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := req(a, a.route("callback")+"?code="+grant+"&state="+state)
			r.AddCookie(c)
			w := httptest.NewRecorder()
			HandleCallback(w, r)
			results <- w.Code
		}()
	}
	wg.Wait()
	close(results)
	successes := 0
	for status := range results {
		if status == 303 {
			successes++
		}
	}
	require.Equal(t, 1, successes)
	require.Equal(t, 1, count(t))
}

func TestPendingFlowRotationAndRegistrationRollback(t *testing.T) {
	a := fixture(t)
	cookies := []*http.Cookie{}
	for range 9 {
		r := req(a, a.route("start")+"?return=%2Freports")
		for _, c := range cookies {
			r.AddCookie(c)
		}
		w := httptest.NewRecorder()
		HandleStart(w, r)
		require.Equal(t, 303, w.Code, w.Body.String())
		for _, response := range w.Result().Cookies() {
			kept := cookies[:0]
			for _, c := range cookies {
				if c.Name != response.Name {
					kept = append(kept, c)
				}
			}
			cookies = kept
			if response.MaxAge >= 0 {
				cookies = append(cookies, response)
			}
		}
		require.LessOrEqual(t, len(cookies), 6)
	}
	_, err := SaveApp("", AppRequest{Name: "duplicate", Origin: a.Origin, AllowedReturnPaths: []string{"/"}})
	require.Error(t, err)
	var n int
	require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM clients WHERE client_id LIKE 'forward-auth-%'`).Scan(&n))
	require.Equal(t, 1, n)
}

func TestCookieAmbiguityAndEmptyBackendCookie(t *testing.T) {
	a := fixture(t)
	c, f, state := start(t, a)
	grant := code(t, a, f)
	r := req(a, a.route("callback")+"?code="+grant+"&state="+state)
	r.AddCookie(c)
	w := httptest.NewRecorder()
	HandleCallback(w, r)
	require.Equal(t, 303, w.Code)
	var session *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == a.cookieName() {
			session = c
		}
	}
	require.NotNil(t, session)
	check := req(a, "/check")
	check.AddCookie(session)
	success := httptest.NewRecorder()
	HandleCheck(success, check)
	require.Equal(t, 204, success.Code)
	require.Equal(t, "autentico_no_app_cookies=1", success.Header().Get("Cookie"))
	check.AddCookie(&http.Cookie{Name: a.cookieName(), Value: "forged"})
	denied := httptest.NewRecorder()
	HandleCheck(denied, check)
	require.Equal(t, 401, denied.Code)
	// A disabled registration preserves that status on an ordinary edit.
	no := false
	a, err := SaveApp(a.ID, AppRequest{Name: a.Name, Origin: a.Origin, AllowedReturnPaths: a.AllowedReturnPaths, IsActive: &no})
	require.NoError(t, err)
	a, err = SaveApp(a.ID, AppRequest{Name: "Edited", Origin: a.Origin, AllowedReturnPaths: a.AllowedReturnPaths})
	require.NoError(t, err)
	require.False(t, a.IsActive)
}

func TestDeletingAppRemovesSessionsAndDisablesClient(t *testing.T) {
	a := fixture(t)
	c, f, state := start(t, a)
	grant := code(t, a, f)
	r := req(a, a.route("callback")+"?code="+grant+"&state="+state)
	r.AddCookie(c)
	w := httptest.NewRecorder()
	HandleCallback(w, r)
	require.Equal(t, 303, w.Code)
	require.Equal(t, 1, count(t))
	require.NoError(t, DeleteApp(a.ID))
	require.Zero(t, count(t))
	var active bool
	require.NoError(t, db.GetDB().QueryRow(`SELECT is_active FROM clients WHERE client_id=?`, a.ClientID).Scan(&active))
	require.False(t, active)
	denied := httptest.NewRecorder()
	HandleCheck(denied, req(a, "/check"))
	require.Equal(t, 403, denied.Code)
}
