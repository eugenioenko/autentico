package wellknown

import (
	"fmt"
	"net/http"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/model"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// HandleWellKnownConfig handles the .well-known configuration endpoint
// @Summary Get Well-Known Configuration
// @Description Returns the OpenID Connect Well-Known Configuration
// @Tags Well-Known
// @Accept json
// @Produce json
// @Success 200 {object} model.WellKnownConfigResponse
// @Router /.well-known/openid-configuration [get]
func HandleWellKnownConfig(w http.ResponseWriter, r *http.Request) {
	config := config.Get()
	response := model.WellKnownConfigResponse{
		Issuer:                config.AppAuthIssuer,
		AuthorizationEndpoint: fmt.Sprintf("%s/authorize", config.AppAuthIssuer),
		TokenEndpoint:         fmt.Sprintf("%s/token", config.AppAuthIssuer),
		UserInfoEndpoint:      fmt.Sprintf("%s/userinfo", config.AppAuthIssuer),
		JwksURI:               fmt.Sprintf("%s/.well-known/jwks.json", config.AppURL),
		ResponseTypesSupported: []string{
			"code", "token", "id_token", "code token", "code id_token",
		},
		SubjectTypesSupported: []string{
			"public",
		},
		IDTokenSigningAlgValuesSupported: []string{
			"RS256",
		},
		ScopesSupported: []string{
			"openid", "profile", "email",
		},
		TokenEndpointAuthMethodsSupported: []string{
			"client_secret_basic", "client_secret_post",
		},
		ClaimsSupported: []string{
			"sub", "iss", "aud", "exp", "iat", "name", "email",
		},
	}

	utils.WriteApiResponse(w, response, http.StatusOK)
}
