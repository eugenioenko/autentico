package admin

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed all:dist
var distFS embed.FS

// Handler returns an http.Handler that serves the admin SPA.
// Static files are served directly; all other paths fall back to index.html
// so that client-side routing works.
func Handler() http.Handler {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		panic(err)
	}
	fileServer := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Strip the /admin/ prefix
		path := strings.TrimPrefix(r.URL.Path, "/admin")
		if path == "" {
			path = "/"
		}

		// Try to open the file to see if it exists
		if path != "/" {
			trimmed := strings.TrimPrefix(path, "/")
			if f, err := sub.Open(trimmed); err == nil {
				f.Close()
				// File exists — serve it directly
				http.StripPrefix("/admin", fileServer).ServeHTTP(w, r)
				return
			}
		}

		// Fall back to index.html for SPA routing
		r.URL.Path = "/admin/"
		http.StripPrefix("/admin", fileServer).ServeHTTP(w, r)
	})
}
