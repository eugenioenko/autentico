package forwardauth

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/authzsig"
	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/token"
	"github.com/gorilla/securecookie"
	"github.com/rs/xid"
)

const flowAge = 10 * time.Minute

var statePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

type loginFlow struct {
	AppID     string
	Origin    string
	Return    string
	Verifier  string
	Nonce     string
	ExpiresAt int64
}

func privateHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}
func deny(w http.ResponseWriter, status int) {
	if status == 401 {
		w.Header().Set("WWW-Authenticate", `Session realm="Autentico"`)
	}
	http.Error(w, http.StatusText(status), status)
}

// proxyApp authenticates the network peer before reading forwarding metadata.
// RFC 7239 §8.1: forwarding headers supplied by untrusted peers are forgeable.
func proxyApp(w http.ResponseWriter, r *http.Request) *App {
	privateHeaders(w)
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		deny(w, 403)
		return nil
	}
	peer, err := netip.ParseAddr(host)
	trusted := false
	if err == nil {
		for _, prefix := range config.GetBootstrap().TrustedProxies {
			if prefix.Contains(peer.Unmap()) {
				trusted = true
				break
			}
		}
	}
	if !trusted {
		deny(w, 403)
		return nil
	}
	a, err := AppByID(r.PathValue("id"))
	if errors.Is(err, sql.ErrNoRows) {
		deny(w, 403)
		return nil
	}
	if err != nil {
		deny(w, 503)
		return nil
	}
	if !a.IsActive || !a.validStored() {
		deny(w, 403)
		return nil
	}
	u, _ := url.Parse(a.Origin)
	// Reject repeated/list-valued claims; the last hop must overwrite them.
	if singleHeader(r, "X-Forwarded-Host") != u.Host || singleHeader(r, "X-Forwarded-Proto") != u.Scheme {
		deny(w, 403)
		return nil
	}
	return a
}
func singleHeader(r *http.Request, name string) string {
	values := r.Header.Values(name)
	if len(values) != 1 || values[0] == "" || strings.ContainsAny(values[0], "\r\n") {
		return ""
	}
	return values[0]
}
func cookie(r *http.Request, name string) string {
	found := ""
	count := 0
	for _, c := range r.Cookies() {
		if c.Name == name {
			found = c.Value
			count++
		}
	}
	if count != 1 {
		return ""
	}
	return found
}
func browser(r *http.Request, method string) bool {
	return (method == "GET" || method == "HEAD") && strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/html")
}

// HandleCheck godoc
// @Summary Check a protected application's browser session
// @Description Trusted proxy only. Returns 204, 401, 403 or a fail-closed error. redirect=1 permits redirects for HTML GET/HEAD navigation only; nginx must use status-only mode.
// @Tags forward-auth
// @Param id path string true "Protected application ID"
// @Param redirect query string false "Set to 1 for browser login redirects"
// @Success 204 "Allowed; X-Auth-User identifies the user; X-Auth-Email is present only for verified addresses"
// @Failure 401 "Authentication required; X-Autentico-Login supplies the login URL"
// @Failure 403 "Forbidden"
// @Failure 503 "Authentication service unavailable"
// @Router /forward-auth/{id}/check [get]
func HandleCheck(w http.ResponseWriter, r *http.Request) {
	a := proxyApp(w, r)
	if a == nil {
		return
	}
	original := singleHeader(r, "X-Forwarded-Uri")
	method := singleHeader(r, "X-Forwarded-Method")
	if !a.allowReturn(original) || !validMethod(method) {
		deny(w, 403)
		return
	}
	usr, _, err := checkSession(a, cookie(r, a.cookieName()))
	if err != nil {
		if !errors.Is(err, errDenied) {
			deny(w, 503)
			return
		}
		login := a.Origin + a.route("start") + "?return=" + url.QueryEscape(original)
		w.Header().Set("X-Autentico-Login", login)
		// RFC 9110 §15.4.4: never turn a noninteractive or unsafe request
		// into a browser login redirect (or replay its request body).
		if r.URL.Query().Get("redirect") == "1" && browser(r, method) {
			http.Redirect(w, r, login, http.StatusSeeOther)
			return
		}
		w.Header().Set("WWW-Authenticate", `Session realm="Autentico"`)
		deny(w, 401)
		return
	}
	// These values are copied only by the trusted proxy, which must strip
	// incoming identity headers and auth cookies before contacting the app.
	w.Header().Set("X-Auth-User", usr.ID)
	// Unverified profile data must not become a trusted backend account key.
	w.Header().Del("X-Auth-Email")
	if usr.IsEmailVerified && usr.Email != "" {
		w.Header().Set("X-Auth-Email", usr.Email)
	}
	// Cookie is a proxy response-to-request header, not Set-Cookie. Preserve
	// application cookies while withholding our credentials from the backend.
	safeCookies := []string{}
	for _, c := range r.Cookies() {
		if strings.HasPrefix(c.Name, "__Host-autentico_fa_") || strings.HasPrefix(c.Name, "autentico_fa_") || c.Name == config.GetBootstrap().AuthIdpSessionCookieName {
			continue
		}
		safeCookies = append(safeCookies, c.String())
	}
	filtered := strings.Join(safeCookies, "; ")
	if filtered == "" {
		// Caddy/Traefik skip empty response headers when copying them. A
		// harmless marker forces replacement rather than leaking the original.
		filtered = "autentico_no_app_cookies=1"
	}
	w.Header().Set("Cookie", filtered)
	w.WriteHeader(http.StatusNoContent)
}
func validMethod(s string) bool {
	if len(s) == 0 || len(s) > 32 {
		return false
	}
	for _, c := range s {
		if c < 'A' || c > 'Z' {
			return false
		}
	}
	return true
}

func codec() (*securecookie.SecureCookie, error) {
	secret := config.GetBootstrap().AuthCSRFProtectionSecretKey
	if len(secret) < 32 {
		return nil, fmt.Errorf("missing persistent CSRF key")
	}
	sign := sha256.Sum256([]byte("autentico-forward-auth-sign:" + secret))
	encrypt := sha256.Sum256([]byte("autentico-forward-auth-encrypt:" + secret))
	return securecookie.New(sign[:], encrypt[:]).MaxAge(int(flowAge.Seconds())), nil
}
func flowName(a *App, state string) string { return a.cookieName() + "_flow_" + state }
func setCookie(w http.ResponseWriter, a *App, name, value string, age int) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", Secure: a.secure(), HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: age})
}

// Keep at most six pending transactions without turning abandoned or forced
// login starts into a ten-minute lockout. Authentication remains browser-bound.
func pruneFlows(w http.ResponseWriter, r *http.Request, a *App, sc *securecookie.SecureCookie) {
	type pendingFlow struct {
		name    string
		expires int64
	}
	pending := []pendingFlow{}
	prefix := a.cookieName() + "_flow_"
	now := time.Now().Unix()
	for _, c := range r.Cookies() {
		if !strings.HasPrefix(c.Name, prefix) {
			continue
		}
		var flow loginFlow
		if !statePattern.MatchString(strings.TrimPrefix(c.Name, prefix)) || sc.Decode(c.Name, c.Value, &flow) != nil || flow.AppID != a.ID || flow.Origin != a.Origin || flow.ExpiresAt <= now || flow.ExpiresAt > now+int64(flowAge.Seconds()) {
			setCookie(w, a, c.Name, "", -1)
			continue
		}
		pending = append(pending, pendingFlow{c.Name, flow.ExpiresAt})
	}
	// Equal deadlines retain browser cookie creation order (RFC 6265 §5.4).
	sort.SliceStable(pending, func(i, j int) bool { return pending[i].expires < pending[j].expires })
	for len(pending) >= 6 {
		setCookie(w, a, pending[0].name, "", -1)
		pending = pending[1:]
	}
}

// HandleStart godoc
// @Summary Start browser login for a protected application
// @Description App-origin route, restricted to trusted proxies. Sets a temporary encrypted browser cookie and redirects to existing authorization/login policy.
// @Tags forward-auth
// @Param id path string true "Application ID"
// @Param return query string true "Allowed local path and query"
// @Success 303 "Central authorization redirect"
// @Failure 400 "Unsafe destination"
// @Failure 403 "Untrusted proxy or origin"
// @Failure 429 "Authentication rate limit exceeded"
// @Router /_autentico/{id}/start [get]
func HandleStart(w http.ResponseWriter, r *http.Request) {
	a := proxyApp(w, r)
	if a == nil {
		return
	}
	dest := r.URL.Query().Get("return")
	if !a.allowReturn(dest) || len(r.URL.Query()["return"]) != 1 {
		deny(w, 400)
		return
	}
	sc, err := codec()
	if err != nil {
		deny(w, 503)
		return
	}
	state, err := authcode.GenerateSecureCode()
	if err != nil {
		deny(w, 503)
		return
	}
	verifier, err := authcode.GenerateSecureCode()
	if err != nil {
		deny(w, 503)
		return
	}
	nonce, err := authcode.GenerateSecureCode()
	if err != nil {
		deny(w, 503)
		return
	}
	flow := loginFlow{AppID: a.ID, Origin: a.Origin, Return: dest, Verifier: verifier, Nonce: nonce, ExpiresAt: time.Now().Add(flowAge).Unix()}
	value, err := sc.Encode(flowName(a, state), flow)
	if err != nil {
		deny(w, 503)
		return
	}
	sum := sha256.Sum256([]byte(verifier))
	params := url.Values{"client_id": {a.ClientID}, "redirect_uri": {a.callback()}, "response_type": {"code"}, "scope": {"openid"}, "state": {state}, "nonce": {nonce}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}}
	bs := config.GetBootstrap()
	pruneFlows(w, r, a, sc)
	setCookie(w, a, flowName(a, state), value, int(flowAge.Seconds()))
	http.Redirect(w, r, bs.AppURL+bs.AppOAuthPath+"/authorize?"+params.Encode(), http.StatusSeeOther)
}

// HandleCallback redeems a same-issuer code directly: it creates only a proxy
// session, never OAuth access/refresh credentials for the protected backend.
// @Summary Complete browser login for a protected application
// @Description Trusted proxy app-origin callback. Checks state, browser binding, nonce, PKCE and current policy before atomically consuming the code and issuing an app-only cookie.
// @Tags forward-auth
// @Param id path string true "Application ID"
// @Param code query string true "Authorization code"
// @Param state query string true "Browser transaction state"
// @Success 303 "Clean original destination"
// @Failure 400 "Invalid or replayed callback"
// @Failure 403 "Untrusted proxy, origin or client policy"
// @Router /_autentico/{id}/callback [get]
func HandleCallback(w http.ResponseWriter, r *http.Request) {
	a := proxyApp(w, r)
	if a == nil {
		return
	}
	state := r.URL.Query().Get("state")
	if !statePattern.MatchString(state) || len(r.URL.Query()["state"]) != 1 {
		deny(w, 400)
		return
	}
	sc, err := codec()
	if err != nil {
		deny(w, 503)
		return
	}
	var flow loginFlow
	// RFC 9700 §4.7: require the initiating browser before examining or
	// consuming a code; a stolen callback must not authenticate another browser.
	if sc.Decode(flowName(a, state), cookie(r, flowName(a, state)), &flow) != nil || flow.AppID != a.ID || flow.Origin != a.Origin || !a.allowReturn(flow.Return) || flow.ExpiresAt <= time.Now().Unix() || flow.ExpiresAt > time.Now().Add(flowAge).Unix() {
		deny(w, 400)
		return
	}
	if r.URL.Query().Get("error") != "" {
		setCookie(w, a, flowName(a, state), "", -1)
		deny(w, 401)
		return
	}
	if len(r.URL.Query()["code"]) != 1 || !statePattern.MatchString(r.URL.Query().Get("code")) {
		deny(w, 400)
		return
	}
	sum := sha256.Sum256([]byte(flow.Verifier))
	if _, err := client.ValidateAuthorization(authzsig.AuthorizeParams{ClientID: a.ClientID, RedirectURI: a.callback(), Scope: "openid", Nonce: flow.Nonce, CodeChallenge: base64.RawURLEncoding.EncodeToString(sum[:]), CodeChallengeMethod: "S256"}); err != nil {
		deny(w, 403)
		return
	}
	usr, code, err := token.UserByAuthorizationCode(w, token.TokenRequest{ClientID: a.ClientID, RedirectURI: a.callback(), Code: r.URL.Query().Get("code"), CodeVerifier: flow.Verifier, GrantType: "authorization_code"})
	if err != nil {
		return
	}
	// RFC 7636 §4.6 / OIDC Core §3.1.2.3: require the exact request's
	// nonce, S256 binding and an active completed central authentication.
	if code.Nonce != flow.Nonce || code.CodeChallengeMethod != "S256" || code.IdpSessionID == "" {
		deny(w, 400)
		return
	}
	current, err := parentIdentity(a, code.IdpSessionID)
	if err != nil && !errors.Is(err, errDenied) {
		deny(w, 503)
		return
	}
	if err != nil || current.User.ID != usr.ID {
		deny(w, 401)
		return
	}
	credential, err := authcode.GenerateSecureCode()
	if err != nil {
		deny(w, 503)
		return
	}
	ttl, err := time.ParseDuration(a.SessionTTL)
	if err != nil {
		deny(w, 503)
		return
	}
	tx, err := db.GetDB().Begin()
	if err != nil {
		deny(w, 503)
		return
	}
	defer func() { _ = tx.Rollback() }()
	// RFC 6749 §4.1.2: atomic code consumption and session insertion make
	// concurrent redemption single-use, including across server restarts.
	if err = authcode.MarkAuthCodeAsUsedTx(tx, code.Code); err != nil {
		if errors.Is(err, authcode.ErrCodeUsed) {
			deny(w, 400)
		} else {
			deny(w, 503)
		}
		return
	}
	// RFC 6749 §4.1.2: claim the writer first, then recheck the stored expiry,
	// exactly as token issuance does. Rollback restores an expired code's state.
	var expires time.Time
	if err = tx.QueryRow(`SELECT expires_at FROM auth_codes WHERE code=?`, code.Code).Scan(&expires); err != nil {
		deny(w, 503)
		return
	}
	now := time.Now().UTC()
	if !now.Before(expires) {
		deny(w, 400)
		return
	}
	result, err := tx.Exec(`INSERT INTO forward_auth_sessions(id,app_id,idp_session_id,token_hash,created_at,last_activity_at,expires_at)
        SELECT ?,p.id,i.id,?,?,?,? FROM protected_apps p JOIN clients c ON c.client_id=p.client_id JOIN idp_sessions i ON i.id=? JOIN users u ON u.id=i.user_id
        WHERE p.id=? AND p.is_active=TRUE AND c.is_active=TRUE AND i.deactivated_at IS NULL AND u.deactivated_at IS NULL AND i.user_id=?`, xid.New().String(), hash(credential), now, now, now.Add(ttl), code.IdpSessionID, a.ID, usr.ID)
	if err != nil {
		deny(w, 503)
		return
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		deny(w, 401)
		return
	}
	if old := cookie(r, a.cookieName()); old != "" {
		if _, err = tx.Exec(`UPDATE forward_auth_sessions SET revoked_at=? WHERE app_id=? AND token_hash=? AND revoked_at IS NULL`, now, a.ID, hash(old)); err != nil {
			deny(w, 503)
			return
		}
	}
	if err = tx.Commit(); err != nil {
		deny(w, 503)
		return
	}
	setCookie(w, a, flowName(a, state), "", -1)
	setCookie(w, a, a.cookieName(), credential, int(ttl.Seconds()))
	http.Redirect(w, r, flow.Return, http.StatusSeeOther)
}

// HandleLogout revokes only the current app session. Same-origin POST and an
// Origin check prevent cross-site logout; central logout remains authoritative.
// @Summary Revoke this browser's protected-application session
// @Tags forward-auth
// @Param id path string true "Application ID"
// @Param Origin header string true "Exact registered application origin"
// @Success 204 "Session revoked and cookie cleared"
// @Failure 403 "Untrusted proxy, origin or cross-origin logout"
// @Router /_autentico/{id}/logout [post]
func HandleLogout(w http.ResponseWriter, r *http.Request) {
	a := proxyApp(w, r)
	if a == nil {
		return
	}
	if singleHeader(r, "Origin") != a.Origin {
		deny(w, 403)
		return
	}
	if _, err := db.GetDB().Exec(`UPDATE forward_auth_sessions SET revoked_at=? WHERE app_id=? AND token_hash=? AND revoked_at IS NULL`, time.Now().UTC(), a.ID, hash(cookie(r, a.cookieName()))); err != nil {
		deny(w, 503)
		return
	}
	setCookie(w, a, a.cookieName(), "", -1)
	w.WriteHeader(http.StatusNoContent)
}
