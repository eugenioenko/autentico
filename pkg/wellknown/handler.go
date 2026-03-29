package wellknown

import (
	"fmt"
	"net/http"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/key"
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
	bs := config.GetBootstrap()
	issuer := bs.AppAuthIssuer
	response := model.WellKnownConfigResponse{
		Issuer:                issuer,
		AuthorizationEndpoint: fmt.Sprintf("%s/authorize", issuer),
		TokenEndpoint:         fmt.Sprintf("%s/token", issuer),
		UserInfoEndpoint:      fmt.Sprintf("%s/userinfo", issuer),
		RegistrationEndpoint:  fmt.Sprintf("%s/register", issuer),
		EndSessionEndpoint:    fmt.Sprintf("%s/logout", issuer),
		JwksURI:               fmt.Sprintf("%s/.well-known/jwks.json", bs.AppAuthIssuer),
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
			"openid", "profile", "email", "address", "phone", "offline_access",
		},
		TokenEndpointAuthMethodsSupported: []string{
			"client_secret_basic", "client_secret_post",
		},
		ClaimsSupported: []string{
			"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "sid", "acr",
			"name", "preferred_username", "given_name", "family_name", "middle_name",
			"nickname", "profile", "picture", "website", "gender", "birthdate",
			"locale", "zoneinfo", "updated_at",
			"email", "email_verified",
			"phone_number",
			"address",
		},
		GrantTypesSupported:       []string{"authorization_code", "refresh_token", "password"},
		AcrValuesSupported:        []string{"1"},
		RequestParameterSupported: false,
		// RFC 8414 §2
		IntrospectionEndpoint:         fmt.Sprintf("%s/introspect", issuer),
		RevocationEndpoint:            fmt.Sprintf("%s/revoke", issuer),
		CodeChallengeMethodsSupported: []string{"S256"},
	}

	utils.WriteApiResponse(w, response, http.StatusOK)
}

// HandleJWKS returns the JWKS (JSON Web Key Set) for OIDC clients
// @Summary Get JWKS
// @Description Returns the JSON Web Key Set for verifying JWTs
// @Tags Well-Known
// @Accept json
// @Produce json
// @Success 200 {object} model.JWKSResponse
// @Router /oauth2/.well-known/jwks.json [get]
func HandleJWKS(w http.ResponseWriter, r *http.Request) {
	kid := config.GetBootstrap().AuthJwkCertKeyID
	kMap := key.GetRSAPublicKeyJWK(kid)
	jwk := model.JWK{
		Kty: kMap["kty"],
		Kid: kMap["kid"],
		Use: kMap["use"],
		Alg: kMap["alg"],
		N:   kMap["n"],
		E:   kMap["e"],
	}
	jwks := model.JWKSResponse{
		Keys: []model.JWK{jwk},
	}
	utils.WriteApiResponse(w, jwks, http.StatusOK)
}
