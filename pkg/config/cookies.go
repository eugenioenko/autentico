package config

import (
	"fmt"
	"net/http"
	"strings"
)

// HostCookieName preserves the automatic host-only prefix used by browser
// bindings and app sessions. Callers also set Secure, Path=/ and no Domain.
func HostCookieName(base string, secure bool) string {
	if secure {
		return "__Host-" + base
	}
	return base
}

// validateCookieNames rejects unusable or colliding new cookie settings before
// publishing bootstrap configuration. Existing IdP/refresh naming is retained.
func (bs BootstrapConfig) validateCookieNames() error {
	settings := []struct{ env, name string }{
		{"AUTENTICO_CSRF_COOKIE_NAME", bs.AuthCSRFCookieName},
		{"AUTENTICO_TRUSTED_DEVICE_COOKIE_NAME", bs.AuthTrustedDeviceCookieName},
		{"AUTENTICO_FEDERATION_COOKIE_NAME", bs.AuthFederationCookieName},
		{"AUTENTICO_PASSKEY_REGISTRATION_COOKIE_NAME", bs.AuthPasskeyRegistrationCookieName},
		{"AUTENTICO_FORWARD_AUTH_COOKIE_PREFIX", bs.AuthForwardAuthCookiePrefix},
	}
	for _, setting := range settings {
		// RFC 6265 §4.1.1: cookie names are HTTP tokens, never header syntax.
		if len(setting.name) > 128 || (&http.Cookie{Name: setting.name}).Valid() != nil {
			return fmt.Errorf("%s must be an HTTP cookie token of 1–128 ASCII bytes", setting.env)
		}
		// Browser prefix requirements must not silently drop insecure cookies
		// or bypass the automatic __Host- naming and host-only attributes.
		lower := strings.ToLower(setting.name)
		if strings.HasPrefix(lower, "__host-") || strings.HasPrefix(lower, "__secure-") || strings.HasPrefix(lower, "__http-") {
			return fmt.Errorf("%s must be a base name without a reserved browser prefix", setting.env)
		}
	}
	seen := map[string]string{}
	for _, cookie := range []struct{ env, name string }{
		{"AUTENTICO_IDP_SESSION_COOKIE_NAME", bs.AuthIdpSessionCookieName},
		{"AUTENTICO_REFRESH_TOKEN_COOKIE_NAME", bs.AuthRefreshTokenCookieName},
		{"AUTENTICO_CSRF_COOKIE_NAME", bs.AuthCSRFCookieName},
		{"AUTENTICO_TRUSTED_DEVICE_COOKIE_NAME", bs.AuthTrustedDeviceCookieName},
		{"AUTENTICO_FEDERATION_COOKIE_NAME", HostCookieName(bs.AuthFederationCookieName, bs.AuthIdpSessionSecureCookie)},
		{"AUTENTICO_PASSKEY_REGISTRATION_COOKIE_NAME", HostCookieName(bs.AuthPasskeyRegistrationCookieName, bs.AuthCSRFSecureCookie)},
	} {
		// Keep the pre-existing IdP/refresh configuration semantics. New
		// cookie settings may not collide with either legacy setting.
		if previous, ok := seen[cookie.name]; ok && cookie.env != "AUTENTICO_REFRESH_TOKEN_COOKIE_NAME" {
			return fmt.Errorf("%s collides with %s", cookie.env, previous)
		}
		seen[cookie.name] = cookie.env
		if strings.HasPrefix(cookie.name, bs.AuthForwardAuthCookiePrefix) || strings.HasPrefix(cookie.name, "__Host-"+bs.AuthForwardAuthCookiePrefix) {
			return fmt.Errorf("AUTENTICO_FORWARD_AUTH_COOKIE_PREFIX overlaps %s", cookie.env)
		}
	}
	return nil
}
