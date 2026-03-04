package account

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
	req := httptest.NewRequest("GET", "/account/dashboard", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, strings.ToLower(rr.Body.String()), "<!doctype html>")

	// Test static file
	req = httptest.NewRequest("GET", "/account/vite.svg", nil)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	
	// Test root
	req = httptest.NewRequest("GET", "/account/", nil)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHandler_Paths(t *testing.T) {
	handler := Handler()

	// 1. Test /account/ (with trailing slash)
	req := httptest.NewRequest("GET", "/account/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Account")

	// 2. Test /account/nonexistent (should fallback to index.html for SPA)
	req = httptest.NewRequest("GET", "/account/nonexistent", nil)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Account")

	// 3. Test /account/index.html (direct file access)
	// http.FileServer redirects /index.html to / (301)
	req = httptest.NewRequest("GET", "/account/index.html", nil)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusMovedPermanently, rr.Code)
}
