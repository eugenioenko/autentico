package middleware

import (
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/reqid"
)

var (
	silentPrefixes     []string
	silentPrefixesOnce sync.Once
)

func getSilentPrefixes() []string {
	silentPrefixesOnce.Do(func() {
		silentPrefixes = []string{
			"/admin/assets/",
			"/account/assets/",
			config.GetBootstrap().AppOAuthPath + "/static/",
			"/admin/favicon.svg",
			"/account/favicon.svg",
			"/.well-known/appspecific/",
		}
	})
	return silentPrefixes
}

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
		// Skip logging for static asset GET requests served by embedded file servers.
		// These are fixed mount points — no API or auth paths share these prefixes.
		if r.Method == http.MethodGet {
			p := r.URL.Path
			for _, prefix := range getSilentPrefixes() {
				if strings.HasPrefix(p, prefix) {
					next.ServeHTTP(w, r)
					return
				}
			}
		}

		start := time.Now()
		ww := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(ww, r)

		duration := time.Since(start)

		slog.Info("request",
			"request_id", reqid.Get(r.Context()),
			"method", r.Method,
			"url", r.URL.String(),
			"status", ww.statusCode,
			"duration_ms", duration.Milliseconds(),
		)
	})
}
