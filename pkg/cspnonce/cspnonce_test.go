package cspnonce

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMiddleware_InjectsNonce(t *testing.T) {
	var captured string
	handler := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = Get(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.NotEmpty(t, captured, "nonce should be injected into context")
	// 16 bytes base64-encoded = 24 characters
	assert.Len(t, captured, 24, "nonce should be 24 chars (16 bytes base64)")
}

func TestMiddleware_UniquePerRequest(t *testing.T) {
	var nonce1, nonce2 string
	handler := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if nonce1 == "" {
			nonce1 = Get(r.Context())
		} else {
			nonce2 = Get(r.Context())
		}
		w.WriteHeader(http.StatusOK)
	}))

	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	handler.ServeHTTP(httptest.NewRecorder(), req1)

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	handler.ServeHTTP(httptest.NewRecorder(), req2)

	assert.NotEmpty(t, nonce1)
	assert.NotEmpty(t, nonce2)
	assert.NotEqual(t, nonce1, nonce2, "each request must get a unique nonce")
}

func TestGet_EmptyWithoutMiddleware(t *testing.T) {
	nonce := Get(context.Background())
	assert.Empty(t, nonce, "Get should return empty string without middleware")
}
