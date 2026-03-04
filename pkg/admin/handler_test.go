package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHandler(t *testing.T) {
	handler := Handler()

	// Test index.html fallback
	req := httptest.NewRequest("GET", "/admin/dashboard", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, strings.ToLower(rr.Body.String()), "<!doctype html>")

	// Test static file (favicon.svg should exist in dist)
	req = httptest.NewRequest("GET", "/admin/favicon.svg", nil)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	
	// Test docs.html mapping
	req = httptest.NewRequest("GET", "/admin/docs", nil)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	// Even if docs.html doesn't exist, it should still return 200 (falling back to index.html or serving it if it exists)
	assert.Equal(t, http.StatusOK, rr.Code)

	// Test root
	req = httptest.NewRequest("GET", "/admin/", nil)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}
