package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/cspnonce"
	"github.com/stretchr/testify/assert"
)

func TestSecurityHeadersMiddleware(t *testing.T) {
	handler := SecurityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, "DENY", rr.Header().Get("X-Frame-Options"))
	assert.Equal(t, "nosniff", rr.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", rr.Header().Get("Pragma"))
}

func TestSecurityHeaders_CanBeOverridden(t *testing.T) {
	// Static asset handlers override Cache-Control after the middleware sets it.
	handler := SecurityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/static/app.js", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, "public, max-age=86400", rr.Header().Get("Cache-Control"))
}

func TestSecurityHeaders_CSPNonce(t *testing.T) {
	// When cspnonce.Middleware runs first, SecurityHeadersMiddleware should
	// include the nonce in script-src instead of 'unsafe-inline'.
	inner := SecurityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	handler := cspnonce.Middleware(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	csp := rr.Header().Get("Content-Security-Policy")
	assert.Contains(t, csp, "script-src 'self' 'nonce-", "CSP should contain nonce-based script-src")
	// Extract the script-src directive and verify it does not contain 'unsafe-inline'
	scriptSrc := extractDirective(csp, "script-src")
	assert.NotContains(t, scriptSrc, "unsafe-inline", "script-src should not contain 'unsafe-inline'")
	// style-src should still allow 'unsafe-inline'
	assert.Contains(t, csp, "style-src 'self' 'unsafe-inline'", "style-src should retain 'unsafe-inline'")
}

func TestSecurityHeaders_CSPWithoutNonce(t *testing.T) {
	// Without cspnonce.Middleware, script-src should be 'self' only (no unsafe-inline).
	handler := SecurityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	csp := rr.Header().Get("Content-Security-Policy")
	scriptSrc := extractDirective(csp, "script-src")
	assert.Contains(t, scriptSrc, "'self'")
	assert.NotContains(t, scriptSrc, "unsafe-inline", "script-src should not contain 'unsafe-inline'")
}

// extractDirective returns the value portion of a CSP directive (e.g. "script-src")
// from a full Content-Security-Policy header string.
func extractDirective(csp, directive string) string {
	for _, part := range strings.Split(csp, ";") {
		trimmed := strings.TrimSpace(part)
		if strings.HasPrefix(trimmed, directive+" ") {
			return trimmed
		}
	}
	return ""
}

func TestSecurityHeaders_CSPNonceUnique(t *testing.T) {
	// Each request should get a different nonce in the CSP header.
	inner := SecurityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	handler := cspnonce.Middleware(inner)

	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)

	csp1 := rr1.Header().Get("Content-Security-Policy")
	csp2 := rr2.Header().Get("Content-Security-Policy")

	// Extract nonces
	extractNonce := func(csp string) string {
		idx := strings.Index(csp, "'nonce-")
		if idx < 0 {
			return ""
		}
		rest := csp[idx+7:]
		end := strings.Index(rest, "'")
		if end < 0 {
			return ""
		}
		return rest[:end]
	}

	nonce1 := extractNonce(csp1)
	nonce2 := extractNonce(csp2)
	assert.NotEmpty(t, nonce1)
	assert.NotEmpty(t, nonce2)
	assert.NotEqual(t, nonce1, nonce2, "each request should have a unique CSP nonce")
}
