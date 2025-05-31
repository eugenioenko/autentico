package utils

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name           string
		xForwardedFor  string
		remoteAddr     string
		expectedClient string
	}{
		{"With X-Forwarded-For", "192.168.1.1", "127.0.0.1:8888", "192.168.1.1"},
		{"Without X-Forwarded-For", "", "127.0.0.1:8888", "127.0.0.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("X-Forwarded-For", tt.xForwardedFor)
			req.RemoteAddr = tt.remoteAddr

			clientIP := GetClientIP(req)
			assert.Equal(t, tt.expectedClient, clientIP)
		})
	}
}
