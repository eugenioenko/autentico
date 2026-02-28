package view

import (
	"embed"
	"html/template"
)

//go:embed *.html
var FS embed.FS

// ParseTemplate parses layout.html together with the named page template,
// returning a template set where executing "layout" renders the full page.
func ParseTemplate(name string) (*template.Template, error) {
	return template.ParseFS(FS, "layout.html", name+".html")
}
