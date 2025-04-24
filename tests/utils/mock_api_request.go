package testutils

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

type RouteHandler func(w http.ResponseWriter, r *http.Request)

func MockJSONRequest(t *testing.T, body, method, url string, handler RouteHandler) []byte {
	req := httptest.NewRequest(method, url, bytes.NewBuffer([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler(rr, req)
	return rr.Body.Bytes()
}

func MockApiRequestWithAuth(t *testing.T, body, method, url string, handler RouteHandler, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, url, bytes.NewBuffer([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler(rr, req)
	return rr
}

func MockFormRequest(t *testing.T, formData map[string]string, method, uri string, handler RouteHandler) *httptest.ResponseRecorder {
	form := url.Values{}
	for key, value := range formData {
		form.Set(key, value)
	}

	req := httptest.NewRequest(method, uri, bytes.NewBufferString(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handler(rr, req)
	return rr
}
