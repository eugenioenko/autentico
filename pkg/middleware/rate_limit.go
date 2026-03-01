package middleware

import (
	"net/http"

	"github.com/eugenioenko/autentico/pkg/ratelimit"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// RateLimitMiddleware returns a middleware that enforces per-IP rate limiting
// using the provided Store. Requests that exceed the limit receive a 429
// with a Retry-After: 1 header and an OAuth-style JSON error body.
func RateLimitMiddleware(store *ratelimit.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := utils.GetClientIP(r)
			if !store.Allow(ip) {
				w.Header().Set("Retry-After", "1")
				utils.WriteErrorResponse(w, http.StatusTooManyRequests, "too_many_requests", "Rate limit exceeded, please slow down")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
