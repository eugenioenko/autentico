package e2e

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// A partial PUT must keep a per-client override, and the issued token must reflect it.
func TestClientOverride_PartialUpdateKeepsTokenLifetime(t *testing.T) {
	f := setupAccessFixture(t)
	f.createRestrictedClient(t, "override-api", map[string]any{"access_token_expiration": "1h"})

	// Partial update that omits the override.
	f.updateClient(t, "override-api", map[string]any{"restrict_access": true})

	status, body := passwordGrant(t, f.ts, "override-api", "acc-direct")
	require.Equal(t, http.StatusOK, status, body)
	require.EqualValues(t, 3600, body["expires_in"], "omitted override must still apply to issued tokens")

	// Explicit null clears the override: the token no longer uses the 1h lifetime.
	f.updateClient(t, "override-api", map[string]any{"access_token_expiration": nil})

	status, body = passwordGrant(t, f.ts, "override-api", "acc-direct")
	require.Equal(t, http.StatusOK, status, body)
	require.NotEqualValues(t, 3600, body["expires_in"], "null must clear the override and fall back to the global lifetime")
}
