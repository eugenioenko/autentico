package auth_test

import (
	"autentico/pkg/wellknown"
	testutils "autentico/tests/utils"

	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWellKnownRequest(t *testing.T) {
	expected := "{\"issuer\":\"http://localhost:8080/oauth2\",\"authorization_endpoint\":\"http://localhost:8080/oauth2/authorize\",\"token_endpoint\":\"http://localhost:8080/oauth2/token\",\"userinfo_endpoint\":\"http://localhost:8080/oauth2/userinfo\",\"registration_endpoint\":\"\",\"end_session_endpoint\":\"\",\"jwks_uri\":\"http://localhost:8080/.well-known/jwks.json\",\"response_types_supported\":[\"code\",\"token\",\"id_token\",\"code token\",\"code id_token\"],\"subject_types_supported\":[\"public\"],\"id_token_signing_alg_values_supported\":[\"RS256\"],\"scopes_supported\":[\"openid\",\"profile\",\"email\"],\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\",\"client_secret_post\"],\"claims_supported\":[\"sub\",\"iss\",\"aud\",\"exp\",\"iat\",\"name\",\"email\"]}\n"
	data := testutils.MockApiRequest(t, "", http.MethodGet, "/.well-known/openid-configuration", wellknown.HandleWellKnownConfig)
	assert.Equal(t, string(data), expected)
}
