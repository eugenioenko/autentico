package middleware

import (
	"log/slog"
	"net/http"
	"strings"
	"time"
)

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(statusCode int) {
	rw.statusCode = statusCode
	rw.ResponseWriter.WriteHeader(statusCode)
}

func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		// skip logging for static assets
		if strings.HasPrefix(p, "/admin/assets/") || strings.HasPrefix(p, "/account/assets/") {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()
		ww := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(ww, r)

		duration := time.Since(start)

		slog.Info("request",
			"request_id", GetRequestID(r.Context()),
			"method", r.Method,
			"url", r.URL.String(),
			"status", ww.statusCode,
			"duration_ms", duration.Milliseconds(),
		)
	})
}
