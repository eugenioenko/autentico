package wellknown

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/model"
	"github.com/stretchr/testify/assert"
)

func init() {
	config.Bootstrap.AppURL = "http://localhost:9999"
	config.Bootstrap.AppOAuthPath = "/oauth2"
	config.Bootstrap.AppAuthIssuer = "http://localhost:9999/oauth2"
	config.Bootstrap.AuthJwkCertKeyID = "autentico-key-1"
}

func TestHandleWellKnownConfig(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rr := httptest.NewRecorder()

	HandleWellKnownConfig(rr, req)

	// Verify the response
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "authorization_endpoint")
	assert.Contains(t, rr.Body.String(), "token_endpoint")
	assert.Contains(t, rr.Body.String(), "userinfo_endpoint")
	assert.Contains(t, rr.Body.String(), "registration_endpoint")
}

func TestHandleWellKnownConfigResponse(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rr := httptest.NewRecorder()

	HandleWellKnownConfig(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var response model.WellKnownConfigResponse
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)

	// Verify key fields
	assert.NotEmpty(t, response.Issuer)
	assert.NotEmpty(t, response.AuthorizationEndpoint)
	assert.NotEmpty(t, response.TokenEndpoint)
	assert.NotEmpty(t, response.UserInfoEndpoint)
	assert.Equal(t, "http://localhost:9999/oauth2/.well-known/jwks.json", response.JwksURI)
	assert.Contains(t, response.ResponseTypesSupported, "code")
	assert.Contains(t, response.ScopesSupported, "openid")
	assert.Contains(t, response.TokenEndpointAuthMethodsSupported, "client_secret_basic")
	assert.Equal(t, []string{"none", "login", "create"}, response.PromptValuesSupported)
}

// TestHandleWellKnownConfig_GrantTypesSupported verifies that the discovery document
// includes grant_types_supported per RFC 8414 §2.
func TestHandleWellKnownConfig_GrantTypesSupported(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rr := httptest.NewRecorder()

	HandleWellKnownConfig(rr, req)

	var response model.WellKnownConfigResponse
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)

	assert.Contains(t, response.GrantTypesSupported, "authorization_code")
	assert.Contains(t, response.GrantTypesSupported, "refresh_token")
	assert.Contains(t, response.GrantTypesSupported, "password")
}

// TestHandleWellKnownConfig_RequestParameterNotSupported verifies that the discovery
// document declares request_parameter_supported: false per OIDC Core §6.
func TestHandleWellKnownConfig_RequestParameterNotSupported(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rr := httptest.NewRecorder()

	HandleWellKnownConfig(rr, req)

	var response model.WellKnownConfigResponse
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)

	assert.False(t, response.RequestParameterSupported)
}

// TestHandleWellKnownConfig_RFC8414_Endpoints verifies that the discovery document
// includes introspection_endpoint, revocation_endpoint, and code_challenge_methods_supported
// per RFC 8414 §2 (lines 318, 350, 376).
func TestHandleWellKnownConfig_RFC8414_Endpoints(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rr := httptest.NewRecorder()

	HandleWellKnownConfig(rr, req)

	var response model.WellKnownConfigResponse
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)

	assert.NotEmpty(t, response.IntrospectionEndpoint, "RFC 8414 §2: introspection_endpoint must be present")
	assert.NotEmpty(t, response.RevocationEndpoint, "RFC 8414 §2: revocation_endpoint must be present")
	assert.Contains(t, response.CodeChallengeMethodsSupported, "S256", "RFC 8414 §2 + RFC 7636: S256 must be advertised")
}

// OIDC Discovery §3: verify all REQUIRED metadata fields are present
func TestHandleWellKnownConfig_RequiredFields(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rr := httptest.NewRecorder()

	HandleWellKnownConfig(rr, req)

	var response model.WellKnownConfigResponse
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)

	// OIDC Discovery §3: REQUIRED fields
	assert.NotEmpty(t, response.Issuer, "issuer is REQUIRED")
	assert.NotEmpty(t, response.AuthorizationEndpoint, "authorization_endpoint is REQUIRED")
	assert.NotEmpty(t, response.TokenEndpoint, "token_endpoint is REQUIRED")
	assert.NotEmpty(t, response.JwksURI, "jwks_uri is REQUIRED")
	assert.NotEmpty(t, response.ResponseTypesSupported, "response_types_supported is REQUIRED")
	assert.NotEmpty(t, response.SubjectTypesSupported, "subject_types_supported is REQUIRED")
	assert.NotEmpty(t, response.IDTokenSigningAlgValuesSupported, "id_token_signing_alg_values_supported is REQUIRED")

	// OIDC Discovery §3: RECOMMENDED / SHOULD fields
	assert.NotEmpty(t, response.UserInfoEndpoint, "userinfo_endpoint SHOULD be present")
	assert.NotEmpty(t, response.ScopesSupported, "scopes_supported SHOULD be present")
	assert.NotEmpty(t, response.ClaimsSupported, "claims_supported SHOULD be present")

	// OIDC Discovery §3: response_types_supported must only list implemented flows
	assert.Contains(t, response.ResponseTypesSupported, "code")
	assert.NotContains(t, response.ResponseTypesSupported, "token", "implicit flow not implemented")
	assert.NotContains(t, response.ResponseTypesSupported, "id_token", "implicit flow not implemented")
}

// OIDC Discovery §3: issuer MUST exactly match the iss claim in all issued tokens.
// Both derive from config.GetBootstrap().AppAuthIssuer.
func TestHandleWellKnownConfig_IssuerMatchesTokenIss(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rr := httptest.NewRecorder()

	HandleWellKnownConfig(rr, req)

	var response model.WellKnownConfigResponse
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)

	// The issuer in discovery must exactly equal what GenerateIDToken/GenerateTokens
	// use as the "iss" claim — both read from config.GetBootstrap().AppAuthIssuer.
	assert.Equal(t, config.GetBootstrap().AppAuthIssuer, response.Issuer,
		"OIDC Discovery §3: issuer must exactly match the iss claim source")
}

// RFC 8414 §2: verify all REQUIRED metadata fields and that OPTIONAL fields
// with values are present as expected.
func TestHandleWellKnownConfig_RFC8414_RequiredFields(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rr := httptest.NewRecorder()

	HandleWellKnownConfig(rr, req)

	// Parse as raw map to check field presence and types
	var raw map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &raw)
	assert.NoError(t, err)

	// RFC 8414 §2: REQUIRED fields
	assert.Contains(t, raw, "issuer", "RFC 8414 §2: issuer is REQUIRED")
	assert.Contains(t, raw, "authorization_endpoint", "RFC 8414 §2: authorization_endpoint is REQUIRED")
	assert.Contains(t, raw, "token_endpoint", "RFC 8414 §2: token_endpoint is REQUIRED")
	assert.Contains(t, raw, "response_types_supported", "RFC 8414 §2: response_types_supported is REQUIRED")

	// RFC 8414 §2: RECOMMENDED
	assert.Contains(t, raw, "scopes_supported", "RFC 8414 §2: scopes_supported is RECOMMENDED")

	// RFC 8414 §2: OPTIONAL but expected for this server
	assert.Contains(t, raw, "jwks_uri")
	assert.Contains(t, raw, "registration_endpoint")
	assert.Contains(t, raw, "grant_types_supported")
	assert.Contains(t, raw, "token_endpoint_auth_methods_supported")
	assert.Contains(t, raw, "introspection_endpoint")
	assert.Contains(t, raw, "revocation_endpoint")
	assert.Contains(t, raw, "code_challenge_methods_supported")

	// RFC 8414 §3: "Claims with zero elements MUST be omitted from the response."
	// Verify all array fields have at least one element.
	for _, arrayField := range []string{
		"response_types_supported", "scopes_supported",
		"token_endpoint_auth_methods_supported", "grant_types_supported",
		"code_challenge_methods_supported",
	} {
		arr, ok := raw[arrayField].([]interface{})
		if ok {
			assert.NotEmpty(t, arr, "RFC 8414 §3: %s must not be empty if present", arrayField)
		}
	}
}

// RFC 8414 §3: The "issuer" value returned MUST be identical to the authorization
// server's issuer identifier (simple string comparison).
func TestHandleWellKnownConfig_RFC8414_IssuerIdentity(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rr := httptest.NewRecorder()

	HandleWellKnownConfig(rr, req)

	var response model.WellKnownConfigResponse
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)

	// RFC 8414 §3: issuer must be identical via simple string comparison
	assert.Equal(t, config.GetBootstrap().AppAuthIssuer, response.Issuer,
		"RFC 8414 §3: issuer must be identical to the authorization server's issuer identifier")
}

func TestHandleWellKnownConfig_GroupsScope(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rr := httptest.NewRecorder()

	HandleWellKnownConfig(rr, req)

	var response model.WellKnownConfigResponse
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)

	assert.Contains(t, response.ScopesSupported, "groups", "groups must be in scopes_supported")
}

func TestHandleWellKnownConfig_GroupsClaim(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rr := httptest.NewRecorder()

	HandleWellKnownConfig(rr, req)

	var response model.WellKnownConfigResponse
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)

	assert.Contains(t, response.ClaimsSupported, "groups", "groups must be in claims_supported")
}

func TestHandleJWKS(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/oauth2/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()

	HandleJWKS(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "keys")
	assert.Contains(t, rr.Body.String(), "kty")
	assert.Contains(t, rr.Body.String(), "RS256")
}

func TestHandleJWKSResponse(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/oauth2/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()

	HandleJWKS(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var response model.JWKSResponse
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)

	// Should have at least one key
	assert.NotEmpty(t, response.Keys)

	// Verify key fields
	key := response.Keys[0]
	assert.Equal(t, "RSA", key.Kty)
	assert.Equal(t, "RS256", key.Alg)
	assert.Equal(t, "sig", key.Use)
	assert.NotEmpty(t, key.Kid)
	assert.NotEmpty(t, key.N)
	assert.NotEmpty(t, key.E)
}
