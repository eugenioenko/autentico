package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eugenioenko/autentico/pkg/ratelimit"
	"github.com/stretchr/testify/assert"
)

func okHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func TestRateLimitMiddleware_AllowsWithinLimit(t *testing.T) {
	store := ratelimit.NewStore(5, 10, 20, 20)
	handler := RateLimitMiddleware(store)(http.HandlerFunc(okHandler))

	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(http.MethodPost, "/oauth2/login", nil)
		req.RemoteAddr = "1.2.3.4:9999"
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code, "request %d should be allowed", i+1)
	}
}

func TestRateLimitMiddleware_Blocks429WhenExceeded(t *testing.T) {
	// Burst of 1 so the second request is always denied
	store := ratelimit.NewStore(5, 1, 100, 100)
	handler := RateLimitMiddleware(store)(http.HandlerFunc(okHandler))

	req1 := httptest.NewRequest(http.MethodPost, "/oauth2/login", nil)
	req1.RemoteAddr = "1.2.3.4:9999"
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	assert.Equal(t, http.StatusOK, rr1.Code)

	req2 := httptest.NewRequest(http.MethodPost, "/oauth2/login", nil)
	req2.RemoteAddr = "1.2.3.4:9999"
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	assert.Equal(t, http.StatusTooManyRequests, rr2.Code)
	assert.Contains(t, rr2.Body.String(), "too_many_requests")
	assert.Equal(t, "1", rr2.Header().Get("Retry-After"))
}

func TestRateLimitMiddleware_DifferentIPsIndependent(t *testing.T) {
	store := ratelimit.NewStore(5, 1, 100, 100)
	handler := RateLimitMiddleware(store)(http.HandlerFunc(okHandler))

	// Exhaust IP A
	req1 := httptest.NewRequest(http.MethodPost, "/oauth2/login", nil)
	req1.RemoteAddr = "1.1.1.1:9999"
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	assert.Equal(t, http.StatusOK, rr1.Code)

	req2 := httptest.NewRequest(http.MethodPost, "/oauth2/login", nil)
	req2.RemoteAddr = "1.1.1.1:9999"
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	assert.Equal(t, http.StatusTooManyRequests, rr2.Code)

	// IP B should still be allowed
	req3 := httptest.NewRequest(http.MethodPost, "/oauth2/login", nil)
	req3.RemoteAddr = "2.2.2.2:9999"
	rr3 := httptest.NewRecorder()
	handler.ServeHTTP(rr3, req3)
	assert.Equal(t, http.StatusOK, rr3.Code)
}

func TestRateLimitMiddleware_DisabledStore(t *testing.T) {
	store := ratelimit.NewStore(0, 0, 0, 0) // disabled
	handler := RateLimitMiddleware(store)(http.HandlerFunc(okHandler))

	for i := 0; i < 100; i++ {
		req := httptest.NewRequest(http.MethodPost, "/oauth2/login", nil)
		req.RemoteAddr = "1.2.3.4:9999"
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	}
}

func TestRateLimitMiddleware_UsesXForwardedFor(t *testing.T) {
	store := ratelimit.NewStore(5, 1, 100, 100)
	handler := RateLimitMiddleware(store)(http.HandlerFunc(okHandler))

	// First request from forwarded IP — allowed
	req1 := httptest.NewRequest(http.MethodPost, "/oauth2/login", nil)
	req1.Header.Set("X-Forwarded-For", "10.0.0.1")
	req1.RemoteAddr = "127.0.0.1:9999"
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	assert.Equal(t, http.StatusOK, rr1.Code)

	// Second request from same forwarded IP — denied (burst exhausted)
	req2 := httptest.NewRequest(http.MethodPost, "/oauth2/login", nil)
	req2.Header.Set("X-Forwarded-For", "10.0.0.1")
	req2.RemoteAddr = "127.0.0.1:9999"
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	assert.Equal(t, http.StatusTooManyRequests, rr2.Code)
}
