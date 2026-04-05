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
	// RFC 8414 §2: issuer is REQUIRED — must match the iss claim in issued tokens.
	// OIDC Discovery §3: issuer MUST exactly match the iss claim in issued tokens.
	issuer := bs.AppAuthIssuer
	response := model.WellKnownConfigResponse{
		// RFC 8414 §2: REQUIRED fields
		Issuer:                issuer,
		AuthorizationEndpoint: fmt.Sprintf("%s/authorize", issuer),
		TokenEndpoint:         fmt.Sprintf("%s/token", issuer),
		JwksURI:               fmt.Sprintf("%s/.well-known/jwks.json", bs.AppAuthIssuer),
		// RFC 8414 §2: response_types_supported is REQUIRED. Only "code" is
		// implemented; implicit flow variants are not supported.
		ResponseTypesSupported: []string{
			"code",
		},
		// OIDC Discovery §3: REQUIRED
		SubjectTypesSupported: []string{
			"public",
		},
		// OIDC Discovery §3: REQUIRED
		IDTokenSigningAlgValuesSupported: []string{
			"RS256",
		},
		// RFC 8414 §2: RECOMMENDED / OPTIONAL fields
		UserInfoEndpoint:     fmt.Sprintf("%s/userinfo", issuer),
		RegistrationEndpoint: fmt.Sprintf("%s/register", issuer),   // RFC 8414 §2 / RFC 7591
		EndSessionEndpoint:   fmt.Sprintf("%s/logout", issuer),     // RP-Initiated Logout 1.0 §2.1
		ScopesSupported: []string{                                  // RFC 8414 §2: RECOMMENDED
			"openid", "profile", "email", "address", "phone", "offline_access",
		},
		TokenEndpointAuthMethodsSupported: []string{                // RFC 8414 §2: OPTIONAL
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
		// RFC 8414 §2: OPTIONAL (default: ["authorization_code", "implicit"]).
		// We explicitly list supported types to override the default.
		GrantTypesSupported:       []string{"authorization_code", "refresh_token", "password"},
		AcrValuesSupported:        []string{"1"},
		RequestParameterSupported: false, // OIDC Core §6: request objects not supported
		// RFC 8414 §2: OPTIONAL endpoint metadata
		IntrospectionEndpoint:         fmt.Sprintf("%s/introspect", issuer),  // RFC 7662
		RevocationEndpoint:            fmt.Sprintf("%s/revoke", issuer),      // RFC 7009
		CodeChallengeMethodsSupported: []string{"S256"},                      // RFC 7636 §6.2
		PromptValuesSupported:         []string{"none", "login", "create"},
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
