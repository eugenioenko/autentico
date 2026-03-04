package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRequestIDMiddleware(t *testing.T) {
	handler := RequestIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := GetRequestID(r.Context())
		assert.NotEmpty(t, id)
		w.Header().Set("X-Test-Request-ID", id)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	id := rr.Header().Get("X-Test-Request-ID")
	assert.NotEmpty(t, id)
}

func TestGetRequestID_Empty(t *testing.T) {
	id := GetRequestID(context.Background())
	assert.Empty(t, id)
}
