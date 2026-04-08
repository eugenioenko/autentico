package model

// WellKnownConfigResponse is the authorization server metadata document
// per RFC 8414 §2 and OIDC Discovery §3. Served at /.well-known/openid-configuration.
type WellKnownConfigResponse struct {
	// RFC 8414 §2: REQUIRED. Issuer identifier (no query or fragment).
	Issuer string `json:"issuer"`
	// RFC 8414 §2: REQUIRED (unless no grant types use the authorization endpoint).
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	// RFC 8414 §2: REQUIRED (unless only implicit grant type is supported).
	TokenEndpoint string `json:"token_endpoint"`
	// OIDC Discovery §3: RECOMMENDED.
	UserInfoEndpoint string `json:"userinfo_endpoint"`
	// RFC 8414 §2 / RFC 7591: OPTIONAL. Dynamic client registration endpoint.
	RegistrationEndpoint string `json:"registration_endpoint"`
	// OIDC RP-Initiated Logout 1.0 §2.1: end_session_endpoint.
	EndSessionEndpoint string `json:"end_session_endpoint"`
	// RFC 8414 §2: OPTIONAL. JWK Set document URL.
	JwksURI string `json:"jwks_uri"`
	// RFC 8414 §2: REQUIRED. OAuth 2.0 response_type values supported.
	ResponseTypesSupported []string `json:"response_types_supported"`
	// OIDC Discovery §3: REQUIRED.
	SubjectTypesSupported []string `json:"subject_types_supported"`
	// OIDC Discovery §3: REQUIRED.
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	// RFC 8414 §2: RECOMMENDED.
	ScopesSupported []string `json:"scopes_supported"`
	// RFC 8414 §2: OPTIONAL (default: client_secret_basic).
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	// OIDC Discovery §3: RECOMMENDED.
	ClaimsSupported []string `json:"claims_supported"`
	// RFC 8414 §2: OPTIONAL (default: ["authorization_code", "implicit"]).
	GrantTypesSupported []string `json:"grant_types_supported,omitempty"`
	// OIDC Core §3: OPTIONAL.
	AcrValuesSupported []string `json:"acr_values_supported,omitempty"`
	// OIDC Core §3: OPTIONAL.
	RequestParameterSupported bool `json:"request_parameter_supported"`
	// RFC 8414 §2: OPTIONAL. Token introspection endpoint.
	IntrospectionEndpoint string `json:"introspection_endpoint,omitempty"`
	// RFC 8414 §2: OPTIONAL. Token revocation endpoint.
	RevocationEndpoint string `json:"revocation_endpoint,omitempty"`
	// RFC 8414 §2: OPTIONAL. Auth methods for the introspection endpoint.
	IntrospectionEndpointAuthMethodsSupported []string `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	// RFC 8414 §2: OPTIONAL. Auth methods for the revocation endpoint.
	RevocationEndpointAuthMethodsSupported []string `json:"revocation_endpoint_auth_methods_supported,omitempty"`
	// RFC 8414 §2: OPTIONAL. PKCE code challenge methods.
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported,omitempty"`
	// OIDC Discovery §3: OPTIONAL. Prompt values supported.
	PromptValuesSupported []string `json:"prompt_values_supported,omitempty"`
}
