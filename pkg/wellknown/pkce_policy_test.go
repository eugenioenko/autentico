package wellknown

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/model"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestDiscoveryPKCEMethodsFollowEnforcement(t *testing.T) {
	for _, enforce := range []bool{true, false} {
		t.Run(map[bool]string{true: "S256 only", false: "plain opt-in"}[enforce], func(t *testing.T) {
			testutils.WithConfigOverride(t, func() { config.Values.AuthPKCEEnforceSHA256 = enforce })
			rr := httptest.NewRecorder()
			HandleWellKnownConfig(rr, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
			require.Equal(t, http.StatusOK, rr.Code)
			var body model.WellKnownConfigResponse
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
			expected := []string{"S256"}
			if !enforce {
				expected = append(expected, "plain")
			}
			require.Equal(t, expected, body.CodeChallengeMethodsSupported)
		})
	}
}
