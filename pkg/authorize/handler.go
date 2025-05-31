package authorize

import (
	"net/http"

	"autentico/pkg/utils"
)

// HandleAuthorize godoc
// @Summary Authorize a client
// @Description Handles the authorization request and displays the login page
// @Tags authorize
// @Accept json
// @Produce html
// @Param response_type query string true "Response type"
// @Param client_id query string true "Client ID"
// @Param redirect_uri query string true "Redirect URI"
// @Param scope query string false "Scope"
// @Param state query string true "State"
// @Success 200 {string} string "HTML login page"
// @Failure 400 {object} model.ApiError
// @Failure 500 {object} model.ApiError
// @Router /oauth2/authorize [get]
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
		RenderForm(w, r, LoginFormData{
			State:       "",
			RedirectURI: "",
			Error:       err.Error(),
		})
		return
	}

	// Validate redirect_uri
	if !utils.IsValidRedirectURI(request.RedirectURI) {
		RenderForm(w, r, LoginFormData{
			State:       "",
			RedirectURI: "",
			Error:       "Invalid redirect_uri",
		})
		return
	}

	RenderForm(w, r, LoginFormData{
		State:       request.State,
		RedirectURI: request.RedirectURI,
		Error:       "",
	})
}
