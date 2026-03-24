package account

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed all:dist
var distFS embed.FS

// Handler returns an http.Handler that serves the account SPA.
// Static files are served directly; all other paths fall back to index.html
// so that client-side routing works.
func Handler() http.Handler {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Account UI not built. Run 'make build' or 'make account-ui-build'.", http.StatusNotFound)
		})
	}
	fileServer := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Strip the /account/ prefix
		path := strings.TrimPrefix(r.URL.Path, "/account")
		if path == "" {
			path = "/"
		}

		// Try to open the file to see if it exists
		if path != "/" {
			trimmed := strings.TrimPrefix(path, "/")
			if f, err := sub.Open(trimmed); err == nil {
				_ = f.Close()
				// Content-hashed assets are safe to cache for a year
				if strings.HasPrefix(path, "/assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				} else {
					// favicon and other root-level files: 1 day
					w.Header().Set("Cache-Control", "public, max-age=86400")
				}
				http.StripPrefix("/account", fileServer).ServeHTTP(w, r)
				return
			}
		}

		// index.html must not be cached so the browser picks up new asset URLs after a deploy
		w.Header().Set("Cache-Control", "no-cache")
		r.URL.Path = "/account/"
		http.StripPrefix("/account", fileServer).ServeHTTP(w, r)
	})
}
