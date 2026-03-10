package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/stretchr/testify/assert"
)

func TestCSRFMiddleware(t *testing.T) {
	config.Bootstrap.AuthCSRFProtectionSecretKey = "test-csrf-secret-key-32-bytes-ok!!"
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
