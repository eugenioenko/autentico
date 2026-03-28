package view

import (
	"embed"
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
		"safeHTML": func(s template.HTML) template.HTML {
			return s
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
