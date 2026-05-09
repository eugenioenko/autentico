// Package cspnonce generates a cryptographically random CSP nonce per HTTP
// request and stores it in the request context. Templates and middleware
// retrieve the nonce via Get(ctx) to build nonce-based Content-Security-Policy
// headers, eliminating the need for 'unsafe-inline' in script-src.
package cspnonce

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
)

type contextKey string

const nonceKey contextKey = "csp_nonce"

// Middleware generates a 16-byte cryptographically random nonce, base64-encodes
// it, and injects it into the request context. Downstream handlers and
// templates retrieve it via Get(ctx).
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := generate()
		ctx := context.WithValue(r.Context(), nonceKey, nonce)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Get retrieves the CSP nonce from the context. Returns an empty string if
// no nonce is present (e.g. in non-HTTP contexts or tests).
func Get(ctx context.Context) string {
	if n, ok := ctx.Value(nonceKey).(string); ok {
		return n
	}
	return ""
}

// generate returns a base64-encoded random nonce (16 bytes of entropy).
func generate() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand.Read should never fail on a properly configured OS;
		// if it does, fall back to an empty nonce which will cause CSP to
		// block inline scripts (fail-closed).
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}
