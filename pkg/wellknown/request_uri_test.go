package wellknown

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDiscoveryExplicitlyDisablesRequestURI(t *testing.T) {
	rr := httptest.NewRecorder()
	HandleWellKnownConfig(rr, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
	require.Equal(t, http.StatusOK, rr.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	value, present := body["request_uri_parameter_supported"]
	require.True(t, present, "omitting this field advertises support by default")
	require.Equal(t, false, value)
}
