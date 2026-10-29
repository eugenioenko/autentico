package federation

import (
	"net/http"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestConfiguredBrowserCookieProtectsSingleUseFlow(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(map[bool]string{false: "http", true: "https"}[secure], func(t *testing.T) {
			testutils.WithTestDB(t)
			testutils.WithConfigOverride(t, func() {
				config.Bootstrap.AuthFederationCookieName = "tenant_federation"
				config.Bootstrap.AuthIdpSessionSecureCookie = secure
			})
			state := FederationState{ProviderID: "upstream", Nonce: "rp-nonce"}
			signed, c := prepareTestLoginFlow(t, &state, nil)
			name := "tenant_federation"
			if secure {
				name = "__Host-" + name
			}
			require.Equal(t, name, c.Name)
			require.Equal(t, "/", c.Path)
			require.Empty(t, c.Domain)
			require.True(t, c.HttpOnly)
			require.Equal(t, secure, c.Secure)
			require.Equal(t, http.SameSiteLaxMode, c.SameSite)
			legacy := "autentico_federation"
			if secure {
				legacy = "__Host-" + legacy
			}
			require.ErrorIs(t, consumeLoginFlow(flowCallback(&http.Cookie{Name: legacy, Value: c.Value}), &state, signed), errInvalidLoginFlow)
			require.Equal(t, 1, flowRowCount(t))
			require.NoError(t, consumeLoginFlow(flowCallback(c), &state, signed))
			require.ErrorIs(t, consumeLoginFlow(flowCallback(c), &state, signed), errInvalidLoginFlow)
		})
	}
}
