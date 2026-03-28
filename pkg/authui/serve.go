package authui

import (
	"embed"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"sync"
)

//go:embed static templates
var assetsFS embed.FS

var (
	tmplCache = map[string]*template.Template{}
	tmplMu    sync.RWMutex
	funcMap   = template.FuncMap{
		"safeCSS":  func(s string) template.CSS  { return template.CSS(s) },
		"safeHTML": func(s string) template.HTML { return template.HTML(s) },
	}
)

// pageData is implemented by all auth page data structs so RenderPage can
// expose the CSRF token via the X-CSRF-Token response header.
type pageData interface {
	GetCsrfToken() string
}

// StaticHandler serves /auth/ static files (CSS, JS).
func StaticHandler() http.Handler {
	sub, err := fs.Sub(assetsFS, "static")
	if err != nil {
		panic("authui: failed to create sub-filesystem: " + err.Error())
	}
	return http.StripPrefix("/auth/", http.FileServer(http.FS(sub)))
}

// RenderPage executes the named Go template with data and writes the response.
// page must match a template name defined in templates/<page>.html.
func RenderPage(w http.ResponseWriter, page string, data any, statusCode int) {
	tmpl, err := getTemplate(page)
	if err != nil {
		slog.Error("authui: failed to load template", "page", page, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if pd, ok := data.(pageData); ok {
		if token := pd.GetCsrfToken(); token != "" {
			w.Header().Set("X-CSRF-Token", token)
		}
	}
	w.WriteHeader(statusCode)

	if err := tmpl.ExecuteTemplate(w, page, data); err != nil {
		slog.Error("authui: failed to execute template", "page", page, "error", err)
	}
}

func getTemplate(page string) (*template.Template, error) {
	tmplMu.RLock()
	t, ok := tmplCache[page]
	tmplMu.RUnlock()
	if ok {
		return t, nil
	}

	tmplMu.Lock()
	defer tmplMu.Unlock()

	t, err := template.New("").Funcs(funcMap).ParseFS(assetsFS,
		"templates/layout.html",
		"templates/"+page+".html",
	)
	if err != nil {
		return nil, err
	}
	tmplCache[page] = t
	return t, nil
}
