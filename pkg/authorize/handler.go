package authorize

import (
	"html/template"
	"net/http"

	"autentico/pkg/utils"
)

func HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	request := AuthorizeRequest{
		ResponseType: q.Get("response_type"),
		ClientID:     q.Get("client_id"),
		RedirectURI:  q.Get("redirect_uri"),
		Scope:        q.Get("scope"),
		State:        q.Get("state"),
		Nonce:        q.Get("nonce"),
	}

	err := ValidateAuthorizeRequest(request)
	if err != nil {
		response := AuthorizeErrorResponse{Error: "invalid_request", ErrorDescription: err.Error()}
		utils.WriteApiResponse(w, response, http.StatusForbidden)
		return
	}

	tmpl, err := template.ParseFiles("./views/login.html")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// TODO: validate redirect_uri if necessary

	data := map[string]string{
		"State":    request.State,
		"Redirect": request.RedirectURI,
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, "Template Execution Error", http.StatusInternalServerError)
	}
}
