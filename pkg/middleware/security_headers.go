package middleware

import (
	"net/http"
	"strings"
)

// SecurityHeadersMiddleware adds defense-in-depth HTTP headers recommended by
// OWASP. These prevent clickjacking, MIME sniffing, and restrict embedding.
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Swagger/Redoc docs are static read-only HTML with inline scripts;
		// skip CSP and caching headers so the documentation renders correctly.
		if strings.HasPrefix(r.URL.Path, "/swagger/") {
			next.ServeHTTP(w, r)
			return
		}
		// Prevent clickjacking — disallow framing entirely.
		w.Header().Set("X-Frame-Options", "DENY")

		// Prevent MIME-type sniffing — browser must respect Content-Type.
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// Basic Content Security Policy — restrict scripts/styles to same origin.
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data:; font-src 'self' data: https://fonts.gstatic.com; connect-src 'self'; form-action 'self'; frame-ancestors 'none'")

		// Permissions Policy — disable browser features not used by the IdP.
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")

		// Prevent cross-origin embedding.
		w.Header().Set("Cross-Origin-Embedder-Policy", "credentialless")

		// Restrict window references from cross-origin navigations.
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")

		// RFC 6749 §5.1 / RFC 6750 §5.3: prevent caching of sensitive responses.
		// Static asset handlers override this with their own Cache-Control values.
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")

		next.ServeHTTP(w, r)
	})
}
