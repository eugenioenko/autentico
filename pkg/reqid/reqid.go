// Package reqid provides per-request correlation IDs: the middleware that
// mints one and attaches it to the context, and a reader handlers use to
// include the ID in log lines.
package reqid

import (
	"context"
	"net/http"

	"github.com/rs/xid"
)

type contextKey string

const requestIDKey contextKey = "request_id"

// Middleware generates a unique request ID for each request, injects it
// into the context, and sets it on the X-Request-ID response header.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := xid.New().String()
		ctx := context.WithValue(r.Context(), requestIDKey, id)
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Get retrieves the request ID from the context. Returns an empty string
// if no request ID is present.
func Get(ctx context.Context) string {
	if id, ok := ctx.Value(requestIDKey).(string); ok {
		return id
	}
	return ""
}
