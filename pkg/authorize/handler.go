package authorize

import (
	"html/template"
	"net/http"

	"autentico/pkg/utils"
	"autentico/view"

	"github.com/gorilla/csrf"
)

func HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	request := AuthorizeRequest{
		ResponseType:        q.Get("response_type"),
		ClientID:            q.Get("client_id"),
		RedirectURI:         q.Get("redirect_uri"),
		Scope:               q.Get("scope"),
		State:               q.Get("state"),
		Nonce:               q.Get("nonce"),                 // TODO
		CodeChallenge:       q.Get("code_challenge"),        // TODO
		CodeChallengeMethod: q.Get("code_challenge_method"), // TODO
	}

	err := ValidateAuthorizeRequest(request)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusForbidden, "invalid_request", err.Error())
		return
	}

	// Validate redirect_uri
	if !utils.IsValidRedirectURI(request.RedirectURI) {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid redirect_uri")
		return
	}

	tmpl, err := template.New("login").Parse(view.LoginTemplate)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := map[string]any{
		"State":          request.State,
		"Redirect":       request.RedirectURI,
		csrf.TemplateTag: csrf.TemplateField(r),
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, "Template Execution Error", http.StatusInternalServerError)
	}
}
