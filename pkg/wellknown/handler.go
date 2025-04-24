package wellknown

import (
	"fmt"
	"net/http"

	"autentico/pkg/config"
	"autentico/pkg/model"
	"autentico/pkg/utils"
)

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
