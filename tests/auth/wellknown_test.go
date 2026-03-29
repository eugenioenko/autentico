package auth_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/eugenioenko/autentico/pkg/model"
	"github.com/eugenioenko/autentico/pkg/wellknown"
	testutils "github.com/eugenioenko/autentico/tests/utils"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWellKnownConfig_AcrValuesSupported(t *testing.T) {
	data := testutils.MockJSONRequest(t, "", http.MethodGet, "/.well-known/openid-configuration", wellknown.HandleWellKnownConfig)

	var cfg model.WellKnownConfigResponse
	require.NoError(t, json.Unmarshal(data, &cfg))

	assert.Contains(t, cfg.AcrValuesSupported, "1", "acr_values_supported must include '1'")
	assert.Contains(t, cfg.ClaimsSupported, "acr", "claims_supported must include 'acr'")
}

func TestWellKnownRequest(t *testing.T) {
	expected := "{\"issuer\":\"http://localhost:9999/oauth2\",\"authorization_endpoint\":\"http://localhost:9999/oauth2/authorize\",\"token_endpoint\":\"http://localhost:9999/oauth2/token\",\"userinfo_endpoint\":\"http://localhost:9999/oauth2/userinfo\",\"registration_endpoint\":\"http://localhost:9999/oauth2/register\",\"end_session_endpoint\":\"http://localhost:9999/oauth2/logout\",\"jwks_uri\":\"http://localhost:9999/oauth2/.well-known/jwks.json\",\"response_types_supported\":[\"code\"],\"subject_types_supported\":[\"public\"],\"id_token_signing_alg_values_supported\":[\"RS256\"],\"scopes_supported\":[\"openid\",\"profile\",\"email\",\"address\",\"phone\",\"offline_access\"],\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\",\"client_secret_post\"],\"claims_supported\":[\"sub\",\"iss\",\"aud\",\"exp\",\"iat\",\"auth_time\",\"nonce\",\"sid\",\"acr\",\"name\",\"preferred_username\",\"given_name\",\"family_name\",\"middle_name\",\"nickname\",\"profile\",\"picture\",\"website\",\"gender\",\"birthdate\",\"locale\",\"zoneinfo\",\"updated_at\",\"email\",\"email_verified\",\"phone_number\",\"address\"],\"grant_types_supported\":[\"authorization_code\",\"refresh_token\",\"password\"],\"acr_values_supported\":[\"1\"],\"request_parameter_supported\":false,\"introspection_endpoint\":\"http://localhost:9999/oauth2/introspect\",\"revocation_endpoint\":\"http://localhost:9999/oauth2/revoke\",\"code_challenge_methods_supported\":[\"S256\"]}\n"
	data := testutils.MockJSONRequest(t, "", http.MethodGet, "/.well-known/openid-configuration", wellknown.HandleWellKnownConfig)
	assert.Equal(t, string(data), expected)
}
