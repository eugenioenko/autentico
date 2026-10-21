package middleware

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoggingMiddleware(t *testing.T) {
	var logs bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })

	handler := LoggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(
		http.MethodGet,
		"/oauth2/reset-password?token=reset-secret&code=123456&code_verifier=pkce-secret",
		nil,
	)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, logs.String(), `"url":"/oauth2/reset-password"`)
	assert.NotContains(t, logs.String(), "reset-secret")
	assert.NotContains(t, logs.String(), "123456")
	assert.NotContains(t, logs.String(), "pkce-secret")
}
