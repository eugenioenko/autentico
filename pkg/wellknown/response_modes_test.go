package wellknown

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDiscoveryAdvertisesOnlyQueryResponseMode(t *testing.T) {
	rr := httptest.NewRecorder()
	HandleWellKnownConfig(rr, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
	require.Equal(t, http.StatusOK, rr.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	value, present := body["response_modes_supported"]
	require.True(t, present, "omitting this field implies fragment support")
	require.Equal(t, []any{"query"}, value)
}
