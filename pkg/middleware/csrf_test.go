package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/gorilla/csrf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// csrfSecret is a 32-byte key used across all CSRF tests.
const csrfSecret = "test-csrf-secret-key-32-bytes-ok!!"

// setupCSRFMiddleware configures the bootstrap config and returns a CSRF-protected
// handler that records whether the inner handler was called and captures the
// CSRF token from the request context (available on safe methods).
func setupCSRFMiddleware(t *testing.T) (http.Handler, *bool, *string) {
	t.Helper()

	config.Bootstrap.AuthCSRFProtectionSecretKey = csrfSecret
	config.Bootstrap.AuthCSRFSecureCookie = false // plaintext HTTP in tests
	config.Bootstrap.AppHost = ""                 // no trusted-origins check needed
	t.Cleanup(func() {
		config.Bootstrap.AuthCSRFProtectionSecretKey = ""
		config.Bootstrap.AuthCSRFSecureCookie = false
		config.Bootstrap.AppHost = ""
	})

	called := false
	token := ""
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		token = csrf.Token(r)
		w.WriteHeader(http.StatusOK)
	})

	handler := CSRFMiddleware(inner)
	return handler, &called, &token
}

// doGET performs a GET request through the CSRF handler and returns the recorder,
// the CSRF token exposed to the inner handler, and the cookies set on the response.
func doGET(t *testing.T, handler http.Handler, called *bool, token *string) (*httptest.ResponseRecorder, string, []*http.Cookie) {
	t.Helper()

	*called = false
	*token = ""

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	require.True(t, *called, "inner handler must be invoked on GET")
	require.NotEmpty(t, *token, "CSRF token must be available in request context")

	cookies := rr.Result().Cookies()
	return rr, *token, cookies
}

// plaintextRequest marks an http.Request as plaintext HTTP so that gorilla/csrf
// skips the strict Referer/Origin checks it enforces for HTTPS requests.
// In production, the Protect middleware is configured with TrustedOrigins;
// httptest requests have no TLS context, so we must opt in to plaintext mode.
func plaintextRequest(r *http.Request) *http.Request {
	ctx := context.WithValue(r.Context(), csrf.PlaintextHTTPContextKey, true)
	return r.WithContext(ctx)
}

// TestCSRFMiddleware is the original test (GET sets cookie) kept intact.
func TestCSRFMiddleware(t *testing.T) {
	config.Bootstrap.AuthCSRFProtectionSecretKey = csrfSecret
	t.Cleanup(func() { config.Bootstrap.AuthCSRFProtectionSecretKey = "" })
	handler := CSRFMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Verify the response
	assert.Equal(t, http.StatusOK, rr.Code)
	header := rr.Header().Get("Set-Cookie")
	assert.Contains(t, header, "_gorilla_csrf")
}

// TestCSRF_GETSetsCookie verifies that a GET request sets the _gorilla_csrf cookie
// and passes through to the inner handler.
func TestCSRF_GETSetsCookie(t *testing.T) {
	handler, called, token := setupCSRFMiddleware(t)
	rr, csrfToken, cookies := doGET(t, handler, called, token)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.NotEmpty(t, csrfToken)

	// The _gorilla_csrf cookie must be present.
	var found bool
	for _, c := range cookies {
		if c.Name == "_gorilla_csrf" {
			found = true
			break
		}
	}
	assert.True(t, found, "expected _gorilla_csrf cookie to be set")
}

// TestCSRF_SafeMethods verifies that GET, HEAD, and OPTIONS pass through
// without requiring a CSRF token.
func TestCSRF_SafeMethods(t *testing.T) {
	handler, called, _ := setupCSRFMiddleware(t)

	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		t.Run(method, func(t *testing.T) {
			*called = false
			req := httptest.NewRequest(method, "/", nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusOK, rr.Code, "%s should succeed without CSRF token", method)
			assert.True(t, *called, "inner handler must be invoked for %s", method)
		})
	}
}

// TestCSRF_POSTWithoutToken verifies that a POST request without any CSRF token
// is rejected with 403 Forbidden.
func TestCSRF_POSTWithoutToken(t *testing.T) {
	handler, called, _ := setupCSRFMiddleware(t)

	req := plaintextRequest(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("foo=bar")))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.False(t, *called, "inner handler must NOT be invoked without CSRF token")
	assert.Contains(t, rr.Body.String(), "Forbidden - CSRF token invalid")
}

// TestCSRF_POSTWithValidTokenInHeader verifies that a POST with a valid CSRF
// token supplied via the X-CSRF-Token header succeeds.
func TestCSRF_POSTWithValidTokenInHeader(t *testing.T) {
	handler, called, token := setupCSRFMiddleware(t)

	// Step 1: GET to obtain the CSRF token and cookie.
	_, csrfToken, cookies := doGET(t, handler, called, token)

	// Step 2: POST with the token in the header and cookie attached.
	*called = false
	req := plaintextRequest(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("foo=bar")))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", csrfToken)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.True(t, *called, "inner handler must be invoked with valid CSRF token in header")
}

// TestCSRF_POSTWithValidTokenInFormField verifies that a POST with a valid CSRF
// token supplied via the gorilla.csrf.Token form field succeeds.
func TestCSRF_POSTWithValidTokenInFormField(t *testing.T) {
	handler, called, token := setupCSRFMiddleware(t)

	// Step 1: GET to obtain the CSRF token and cookie.
	_, csrfToken, cookies := doGET(t, handler, called, token)

	// Step 2: POST with the token in the form body and cookie attached.
	// Use url.Values to properly encode the token (base64 tokens contain +/= chars).
	*called = false
	formData := url.Values{}
	formData.Set("gorilla.csrf.Token", csrfToken)
	req := plaintextRequest(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(formData.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.True(t, *called, "inner handler must be invoked with valid CSRF token in form field")
}

// TestCSRF_DoubleSubmitCookieRequired verifies that providing the CSRF token in
// the header but WITHOUT the matching cookie results in rejection (403).
// This validates the double-submit cookie pattern: both the cookie and the
// request token are required for successful validation.
func TestCSRF_DoubleSubmitCookieRequired(t *testing.T) {
	handler, called, token := setupCSRFMiddleware(t)

	// Step 1: GET to obtain the CSRF token.
	_, csrfToken, _ := doGET(t, handler, called, token)

	// Step 2: POST with the token in the header but NO cookie.
	*called = false
	req := plaintextRequest(httptest.NewRequest(http.MethodPost, "/", nil))
	req.Header.Set("X-CSRF-Token", csrfToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.False(t, *called, "inner handler must NOT be invoked without CSRF cookie")
}

// TestCSRF_InvalidToken verifies that a POST with a forged/invalid CSRF token
// is rejected with 403 Forbidden.
func TestCSRF_InvalidToken(t *testing.T) {
	handler, called, token := setupCSRFMiddleware(t)

	// Step 1: GET to obtain the cookie.
	_, _, cookies := doGET(t, handler, called, token)

	// Step 2: POST with a completely invalid token but valid cookie.
	*called = false
	req := plaintextRequest(httptest.NewRequest(http.MethodPost, "/", nil))
	req.Header.Set("X-CSRF-Token", "this-is-a-completely-invalid-token")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.False(t, *called, "inner handler must NOT be invoked with invalid CSRF token")
	assert.Contains(t, rr.Body.String(), "Forbidden - CSRF token invalid")
}

// TestCSRF_MismatchedToken verifies that a CSRF token obtained from one session
// (cookie) does not validate against a different session cookie. This ensures
// the masked token is bound to the real token stored in the cookie.
func TestCSRF_MismatchedToken(t *testing.T) {
	handler, called, token := setupCSRFMiddleware(t)

	// Session A: GET to obtain token A and cookie A.
	_, _, cookiesA := doGET(t, handler, called, token)

	// Session B: GET with no cookies to force a new real token / cookie.
	*called = false
	*token = ""
	reqB := httptest.NewRequest(http.MethodGet, "/", nil)
	rrB := httptest.NewRecorder()
	handler.ServeHTTP(rrB, reqB)
	require.True(t, *called)
	tokenB := *token
	require.NotEmpty(t, tokenB)

	// POST: use cookie from session A but token from session B.
	*called = false
	req := plaintextRequest(httptest.NewRequest(http.MethodPost, "/", nil))
	req.Header.Set("X-CSRF-Token", tokenB)
	for _, c := range cookiesA {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.False(t, *called, "inner handler must NOT be invoked with mismatched token/cookie pair")
}

// TestCSRF_UnsafeMethods verifies that all unsafe HTTP methods (POST, PUT,
// PATCH, DELETE) are rejected when no CSRF token is provided.
func TestCSRF_UnsafeMethods(t *testing.T) {
	handler, called, _ := setupCSRFMiddleware(t)

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			*called = false
			req := plaintextRequest(httptest.NewRequest(method, "/", nil))
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusForbidden, rr.Code, "%s without CSRF token should be rejected", method)
			assert.False(t, *called, "inner handler must NOT be invoked for %s without token", method)
		})
	}
}

// TestCSRF_ErrorResponseBody verifies that the custom error handler returns the
// expected error message body.
func TestCSRF_ErrorResponseBody(t *testing.T) {
	handler, called, _ := setupCSRFMiddleware(t)

	req := plaintextRequest(httptest.NewRequest(http.MethodPost, "/", nil))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.False(t, *called)
	// The custom csrfErrorHandler writes exactly this message.
	assert.Contains(t, rr.Body.String(), "Forbidden - CSRF token invalid")
}

// TestCSRF_VaryHeaderSetOnSuccess verifies that the Vary: Cookie header is set
// on successful (safe-method) requests, as gorilla/csrf does this to prevent
// caching of CSRF-protected responses.
func TestCSRF_VaryHeaderSetOnSuccess(t *testing.T) {
	handler, called, token := setupCSRFMiddleware(t)
	rr, _, _ := doGET(t, handler, called, token)

	assert.Contains(t, rr.Header().Get("Vary"), "Cookie")
}

// TestCSRF_TokenUniquePerRequest verifies that the masked CSRF token changes
// on each request (BREACH mitigation), even when using the same underlying
// session cookie.
func TestCSRF_TokenUniquePerRequest(t *testing.T) {
	handler, called, token := setupCSRFMiddleware(t)

	// First GET: obtain token and cookies.
	_, token1, cookies := doGET(t, handler, called, token)

	// Second GET: same cookies, should still get a different masked token.
	*called = false
	*token = ""
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	require.True(t, *called)
	token2 := *token

	assert.NotEmpty(t, token1)
	assert.NotEmpty(t, token2)
	// Masked tokens should differ on each request (one-time pad).
	assert.NotEqual(t, token1, token2, "masked CSRF tokens should differ per request (BREACH mitigation)")

	// Both tokens should still be valid for POST (they unmask to the same real token).
	for i, tk := range []string{token1, token2} {
		*called = false
		postReq := plaintextRequest(httptest.NewRequest(http.MethodPost, "/", nil))
		postReq.Header.Set("X-CSRF-Token", tk)
		for _, c := range cookies {
			postReq.AddCookie(c)
		}
		postRR := httptest.NewRecorder()
		handler.ServeHTTP(postRR, postReq)
		assert.Equal(t, http.StatusOK, postRR.Code, "token %d should be valid for POST", i+1)
		assert.True(t, *called, "inner handler should be called for token %d", i+1)
	}
}
