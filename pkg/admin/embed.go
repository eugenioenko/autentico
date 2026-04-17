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
				_ = f.Close()
				// Content-hashed assets are safe to cache for a year
				if strings.HasPrefix(path, "/assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				} else {
					// favicon and other root-level files: 1 day
					w.Header().Set("Cache-Control", "public, max-age=86400")
				}
				http.StripPrefix("/admin", fileServer).ServeHTTP(w, r)
				return
			}
		}

		// index.html must not be cached so the browser picks up new asset URLs after a deploy
		w.Header().Set("Cache-Control", "no-cache")
		r.URL.Path = "/admin/"
		http.StripPrefix("/admin", fileServer).ServeHTTP(w, r)
	})
}

// ApiDocsHandler serves the Scalar API reference at /api-docs/.
// No build step or embedded file needed — Scalar loads from CDN and
// fetches the swagger spec from /swagger/doc.json at runtime.
func ApiDocsHandler() http.HandlerFunc {
	const page = `<!DOCTYPE html>
<html>
<head>
  <title>Autentico OIDC — API Reference</title>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
</head>
<body>
  <script id="api-reference" data-url="/swagger/doc.json"></script>
  <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
</body>
</html>`
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(page))
	}
}
