package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServerStarts(t *testing.T) {
	ts := startTestServer(t)

	resp, err := ts.Client.Get(ts.BaseURL + "/.well-known/openid-configuration")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var wkConfig model.WellKnownConfigResponse
	err = json.Unmarshal(body, &wkConfig)
	require.NoError(t, err, "response should be valid JSON")

	assert.NotEmpty(t, wkConfig.Issuer)
	assert.NotEmpty(t, wkConfig.AuthorizationEndpoint)
	assert.NotEmpty(t, wkConfig.TokenEndpoint)
	assert.NotEmpty(t, wkConfig.JwksURI)
	assert.Contains(t, wkConfig.Issuer, ts.BaseURL)
}

func TestServerJWKS(t *testing.T) {
	ts := startTestServer(t)

	resp, err := ts.Client.Get(ts.BaseURL + "/.well-known/jwks.json")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var jwks model.JWKSResponse
	err = json.Unmarshal(body, &jwks)
	require.NoError(t, err, "response should be valid JWKS JSON")

	require.NotEmpty(t, jwks.Keys, "JWKS should contain at least one key")

	jwk := jwks.Keys[0]
	assert.Equal(t, "RSA", jwk.Kty)
	assert.Equal(t, "sig", jwk.Use)
	assert.Equal(t, "RS256", jwk.Alg)
	assert.NotEmpty(t, jwk.N, "modulus should not be empty")
	assert.NotEmpty(t, jwk.E, "exponent should not be empty")
	assert.NotEmpty(t, jwk.Kid, "key ID should not be empty")
}

func TestServerAuthorizeRendersLoginPage(t *testing.T) {
	ts := startTestServer(t)

	authorizeURL := ts.BaseURL + "/oauth2/authorize?" + url.Values{
		"response_type": {"code"},
		"client_id":     {"test-client"},
		"redirect_uri":  {"http://localhost:3000/callback"},
		"state":         {"abc123"},
	}.Encode()

	resp, err := ts.Client.Get(authorizeURL)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	bodyStr := string(body)

	// Verify the login form is rendered
	assert.True(t, strings.Contains(bodyStr, "<form"), "response should contain a form element")
	assert.True(t, strings.Contains(bodyStr, `name="username"`), "response should contain username field")
	assert.True(t, strings.Contains(bodyStr, `name="password"`), "response should contain password field")
	assert.True(t, strings.Contains(bodyStr, `name="state"`), "response should contain state hidden field")
	assert.True(t, strings.Contains(bodyStr, `value="abc123"`), "state value should be preserved")

	// Verify CSRF token is present
	csrfToken := getCSRFToken(bodyStr)
	assert.NotEmpty(t, csrfToken, "CSRF token should be present in the login page")
}
