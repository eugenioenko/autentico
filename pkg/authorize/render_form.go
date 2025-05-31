package authorize

import (
	"autentico/view"
	"html/template"
	"net/http"

	"github.com/gorilla/csrf"
)

func RenderForm(w http.ResponseWriter, r *http.Request, form LoginFormData) {

	tmpl, err := template.New("login").Parse(view.LoginTemplate)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := map[string]any{
		"State":          form.State,
		"Redirect":       form.RedirectURI,
		"Error":          form.Error,
		csrf.TemplateTag: csrf.TemplateField(r),
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, "Template Execution Error", http.StatusInternalServerError)
	}
}
