package testutils

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

type RouteHandler func(w http.ResponseWriter, r *http.Request)

func MockApiRequest(t *testing.T, body, method, url string, handler RouteHandler) []byte {
	req := httptest.NewRequest(method, url, bytes.NewBuffer([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler(rr, req)
	return rr.Body.Bytes()
}
