package middleware

import (
	"net/http"

	"github.com/eugenioenko/autentico/pkg/config"
)

// CORSMiddleware handles CORS based on the cors_allowed_origins runtime setting.
// When no origins are configured CORS headers are omitted entirely.
// A wildcard "*" origin sends Access-Control-Allow-Origin: *.
// Specific origins are reflected with Vary and Access-Control-Allow-Credentials.
func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := config.Get()
		origin := r.Header.Get("Origin")

		if origin == "" || len(cfg.CORSAllowedOrigins) == 0 {
			next.ServeHTTP(w, r)
			return
		}

		if cfg.CORSAllowAll {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		} else if originAllowed(origin, cfg.CORSAllowedOrigins) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Add("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		} else {
			next.ServeHTTP(w, r)
			return
		}

		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func originAllowed(origin string, allowed []string) bool {
	for _, a := range allowed {
		if a == origin {
			return true
		}
	}
	return false
}
