package view

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"html/template"
	"io/fs"
	"net/http"

	"github.com/eugenioenko/autentico/pkg/config"
)

//go:embed *.html static/*
var FS embed.FS

// ParseTemplate parses layout.html together with the named page template,
// returning a template set where executing "layout" renders the full page.
func ParseTemplate(name string) (*template.Template, error) {
	tmpl := template.New("layout").Funcs(template.FuncMap{
		"authURL": func(path string) string {
			return config.GetBootstrap().AppOAuthPath + path
		},
		"hasThemeCss": func() bool {
			return config.Get().ThemeCssResolved != ""
		},
		"footerLinks": func() []config.FooterLink {
			return config.Get().FooterLinks
		},
		"brandColor": func() string {
			return config.Get().Theme.BrandColor
		},
	})
	return tmpl.ParseFS(FS, "layout.html", name+".html")
}

// StaticHandler returns an http.Handler that serves files from view/static/.
// Mount it with http.StripPrefix so the handler receives bare file names.
func StaticHandler() http.Handler {
	sub, err := fs.Sub(FS, "static")
	if err != nil {
		panic(err)
	}
	return http.FileServer(http.FS(sub))
}

// ThemeCSSHandler serves admin-supplied theme CSS (theme_css_inline +
// theme_css_file content) with text/css content-type. Serving as an external
// stylesheet — instead of injecting into a page <style> block — eliminates
// the </style> breakout vector that turned admin-controlled CSS into XSS.
func ThemeCSSHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		css := config.Get().ThemeCssResolved
		sum := sha256.Sum256([]byte(css))
		etag := `"` + hex.EncodeToString(sum[:8]) + `"`
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Header().Set("ETag", etag)
		w.Header().Set("Cache-Control", "public, max-age=60, must-revalidate")
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write([]byte(css))
	})
}
