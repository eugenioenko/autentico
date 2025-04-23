package middleware

import (
	"log/slog"
	"net/http"
	"time"
)

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(ww, r)

		duration := time.Since(start)

		slog.Info("HTTP Request Log",
			"details", map[string]interface{}{
				"method":      r.Method,
				"url":         r.URL.String(),
				"remote_addr": r.RemoteAddr,
				"status":      ww.statusCode,
				"duration_ms": duration.Milliseconds(),
				"timestamp":   start.Format(time.RFC3339),
			},
		)
	})
}
