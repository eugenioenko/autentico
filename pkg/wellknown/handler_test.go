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
	assert.NotEmpty(t, response.JwksURI)
	assert.Contains(t, response.ResponseTypesSupported, "code")
	assert.Contains(t, response.ScopesSupported, "openid")
	assert.Contains(t, response.TokenEndpointAuthMethodsSupported, "client_secret_basic")
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

func TestHandleJWKS(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()

	HandleJWKS(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "keys")
	assert.Contains(t, rr.Body.String(), "kty")
	assert.Contains(t, rr.Body.String(), "RS256")
}

func TestHandleJWKSResponse(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
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
