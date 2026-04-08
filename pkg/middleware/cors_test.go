package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/stretchr/testify/assert"
)

func TestCORSMiddleware_Wildcard(t *testing.T) {
	saved := config.Values
	t.Cleanup(func() { config.Values = saved })
	config.Values.CORSAllowedOrigins = []string{"*"}
	config.Values.CORSAllowAll = true

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrapped := CORSMiddleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Origin", "https://app.example.com")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "*", rr.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "GET, POST, PUT, DELETE, OPTIONS", rr.Header().Get("Access-Control-Allow-Methods"))
	assert.Equal(t, "Content-Type, Authorization", rr.Header().Get("Access-Control-Allow-Headers"))
}

func TestCORSMiddleware_SpecificOrigin(t *testing.T) {
	saved := config.Values
	t.Cleanup(func() { config.Values = saved })
	config.Values.CORSAllowedOrigins = []string{"https://app.example.com", "https://admin.example.com"}
	config.Values.CORSAllowAll = false

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrapped := CORSMiddleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Origin", "https://app.example.com")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "https://app.example.com", rr.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", rr.Header().Get("Access-Control-Allow-Credentials"))
	assert.Contains(t, rr.Header().Get("Vary"), "Origin")
}

func TestCORSMiddleware_UnmatchedOrigin(t *testing.T) {
	saved := config.Values
	t.Cleanup(func() { config.Values = saved })
	config.Values.CORSAllowedOrigins = []string{"https://app.example.com"}
	config.Values.CORSAllowAll = false

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrapped := CORSMiddleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Origin", "https://evil.com")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Empty(t, rr.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORSMiddleware_Disabled(t *testing.T) {
	saved := config.Values
	t.Cleanup(func() { config.Values = saved })
	config.Values.CORSAllowedOrigins = nil
	config.Values.CORSAllowAll = false

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrapped := CORSMiddleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Origin", "https://app.example.com")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Empty(t, rr.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORSMiddleware_OptionsRequest(t *testing.T) {
	saved := config.Values
	t.Cleanup(func() { config.Values = saved })
	config.Values.CORSAllowedOrigins = []string{"*"}
	config.Values.CORSAllowAll = true

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Should not be called"))
	})
	wrapped := CORSMiddleware(handler)

	req := httptest.NewRequest(http.MethodOptions, "/test", nil)
	req.Header.Set("Origin", "https://app.example.com")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNoContent, rr.Code)
	assert.Equal(t, "*", rr.Header().Get("Access-Control-Allow-Origin"))
	assert.Empty(t, rr.Body.String())
}
