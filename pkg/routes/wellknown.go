package routes

import (
	"net/http"

	. "autentico/pkg/model"
	"autentico/pkg/utils"
)

func WellKnownConfig(w http.ResponseWriter, r *http.Request) {

	config := WellKnownConfigResponse{
		Issuer:                "https://auth.example.com",
		AuthorizationEndpoint: "https://auth.example.com/oauth2/authorize",
		TokenEndpoint:         "https://auth.example.com/oauth2/token",
		UserInfoEndpoint:      "https://auth.example.com/oauth2/userinfo",
		JwksURI:               "https://auth.example.com/.well-known/jwks.json",
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

	utils.WriteApiResponse(w, config, http.StatusOK)
}
