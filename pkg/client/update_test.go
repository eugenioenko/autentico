package client

import (
	"encoding/json"
	"testing"

	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
)

// A partial update that omits a per-client override must leave it unchanged.
func TestUpdateClient_OmittedOverrideIsPreserved(t *testing.T) {
	testutils.WithTestDB(t)

	created, err := CreateClient(ClientCreateRequest{
		ClientName:   "Original Name",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		GrantTypes:   []string{"authorization_code"},
	})
	assert.NoError(t, err)

	// Set an override using the same JSON shape the API receives.
	var setReq ClientUpdateRequest
	assert.NoError(t, json.Unmarshal([]byte(`{"access_token_expiration":"1h"}`), &setReq))
	assert.NoError(t, UpdateClient(created.ClientID, setReq))

	// Partial update that omits the override.
	var renameReq ClientUpdateRequest
	assert.NoError(t, json.Unmarshal([]byte(`{"client_name":"Renamed"}`), &renameReq))
	assert.NoError(t, UpdateClient(created.ClientID, renameReq))

	updated, err := ClientByClientID(created.ClientID)
	assert.NoError(t, err)
	assert.Equal(t, "Renamed", updated.ClientName)
	got := "<nil>"
	if updated.AccessTokenExpiration != nil {
		got = *updated.AccessTokenExpiration
	}
	assert.Equal(t, "1h", got)
}

// setAllOverrides sends every per-client override in one request (JSON shape the API receives).
func setAllOverrides(t *testing.T, clientID string) {
	t.Helper()
	var req ClientUpdateRequest
	body := `{"access_token_expiration":"1h","refresh_token_expiration":"168h","authorization_code_expiration":"5m",` +
		`"allow_self_signup":true,"sso_session_idle_timeout":"30m","trust_device_enabled":true,"trust_device_expiration":"720h"}`
	assert.NoError(t, json.Unmarshal([]byte(body), &req))
	assert.NoError(t, UpdateClient(clientID, req))
}

func assertAllOverridesSet(t *testing.T, c *Client) {
	t.Helper()
	assert.Equal(t, "1h", deref(c.AccessTokenExpiration))
	assert.Equal(t, "168h", deref(c.RefreshTokenExpiration))
	assert.Equal(t, "5m", deref(c.AuthorizationCodeExpiration))
	assert.NotNil(t, c.AllowSelfSignup)
	assert.True(t, *c.AllowSelfSignup)
	assert.Equal(t, "30m", deref(c.SsoSessionIdleTimeout))
	assert.NotNil(t, c.TrustDeviceEnabled)
	assert.True(t, *c.TrustDeviceEnabled)
	assert.Equal(t, "720h", deref(c.TrustDeviceExpiration))
}

func deref(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

func TestUpdateClient_PartialUpdatePreservesAllOverrides(t *testing.T) {
	testutils.WithTestDB(t)

	created, err := CreateClient(ClientCreateRequest{
		ClientName:   "Original Name",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		GrantTypes:   []string{"authorization_code"},
	})
	assert.NoError(t, err)
	setAllOverrides(t, created.ClientID)

	var req ClientUpdateRequest
	assert.NoError(t, json.Unmarshal([]byte(`{"client_name":"Renamed"}`), &req))
	assert.NoError(t, UpdateClient(created.ClientID, req))

	updated, err := ClientByClientID(created.ClientID)
	assert.NoError(t, err)
	assert.Equal(t, "Renamed", updated.ClientName)
	assertAllOverridesSet(t, updated)
}

func TestUpdateClient_NullClearsOnlyNamedOverride(t *testing.T) {
	testutils.WithTestDB(t)

	created, err := CreateClient(ClientCreateRequest{
		ClientName:   "Original Name",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		GrantTypes:   []string{"authorization_code"},
	})
	assert.NoError(t, err)
	setAllOverrides(t, created.ClientID)

	var req ClientUpdateRequest
	assert.NoError(t, json.Unmarshal([]byte(`{"access_token_expiration":null}`), &req))
	assert.NoError(t, UpdateClient(created.ClientID, req))

	updated, err := ClientByClientID(created.ClientID)
	assert.NoError(t, err)
	assert.Nil(t, updated.AccessTokenExpiration, "explicit null must clear the override")
	assert.Equal(t, "168h", deref(updated.RefreshTokenExpiration))
	assert.Equal(t, "5m", deref(updated.AuthorizationCodeExpiration))
	assert.NotNil(t, updated.AllowSelfSignup)
	assert.True(t, *updated.AllowSelfSignup)
	assert.Equal(t, "30m", deref(updated.SsoSessionIdleTimeout))
	assert.NotNil(t, updated.TrustDeviceEnabled)
	assert.True(t, *updated.TrustDeviceEnabled)
	assert.Equal(t, "720h", deref(updated.TrustDeviceExpiration))
}

func TestUpdateClient_ValueSetsOverride(t *testing.T) {
	testutils.WithTestDB(t)

	created, err := CreateClient(ClientCreateRequest{
		ClientName:   "Original Name",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		GrantTypes:   []string{"authorization_code"},
	})
	assert.NoError(t, err)

	var req ClientUpdateRequest
	assert.NoError(t, json.Unmarshal([]byte(`{"refresh_token_expiration":"24h","allow_self_signup":false,"trust_device_enabled":true}`), &req))
	assert.NoError(t, UpdateClient(created.ClientID, req))

	updated, err := ClientByClientID(created.ClientID)
	assert.NoError(t, err)
	assert.Equal(t, "24h", deref(updated.RefreshTokenExpiration))
	assert.NotNil(t, updated.AllowSelfSignup)
	assert.False(t, *updated.AllowSelfSignup)
	assert.NotNil(t, updated.TrustDeviceEnabled)
	assert.True(t, *updated.TrustDeviceEnabled)
	assert.Nil(t, updated.AccessTokenExpiration)
}

func TestUpdateClient(t *testing.T) {
	testutils.WithTestDB(t)

	// Create a client
	created, err := CreateClient(ClientCreateRequest{
		ClientName:   "Original Name",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		GrantTypes:   []string{"authorization_code"},
	})
	assert.NoError(t, err)

	// Update the client
	err = UpdateClient(created.ClientID, ClientUpdateRequest{
		ClientName: "Updated Name",
	})
	assert.NoError(t, err)

	updated, err := ClientByClientID(created.ClientID)
	assert.NoError(t, err)
	assert.Equal(t, "Updated Name", updated.ClientName)
	// Original values should be preserved
	assert.Equal(t, []string{"http://localhost:3000/callback"}, updated.GetRedirectURIs())
	assert.Equal(t, []string{"authorization_code"}, updated.GetGrantTypes())
}

func TestUpdateClient_NotFound(t *testing.T) {
	testutils.WithTestDB(t)

	err := UpdateClient("nonexistent", ClientUpdateRequest{
		ClientName: "New Name",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestUpdateClient_MultipleFields(t *testing.T) {
	testutils.WithTestDB(t)

	// Create a client
	created, err := CreateClient(ClientCreateRequest{
		ClientName:   "Original Name",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       "openid",
	})
	assert.NoError(t, err)

	// Update multiple fields
	isActive := false
	err = UpdateClient(created.ClientID, ClientUpdateRequest{
		ClientName:   "New Name",
		RedirectURIs: []string{"http://newhost.com/callback"},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		Scopes:       "openid profile email",
		IsActive:     &isActive,
	})
	assert.NoError(t, err)

	updated, err := ClientByClientIDIncludingDisabled(created.ClientID)
	assert.NoError(t, err)
	assert.Equal(t, "New Name", updated.ClientName)
	assert.Equal(t, []string{"http://newhost.com/callback"}, updated.GetRedirectURIs())
	assert.Equal(t, []string{"authorization_code", "refresh_token"}, updated.GetGrantTypes())
	assert.Equal(t, "openid profile email", updated.Scopes)
	assert.False(t, updated.IsActive)
}

func TestUpdateClient_ResponseTypes(t *testing.T) {
	testutils.WithTestDB(t)

	// Create a client
	created, err := CreateClient(ClientCreateRequest{
		ClientName:    "Original Name",
		RedirectURIs:  []string{"http://localhost:3000/callback"},
		ResponseTypes: []string{"code"},
	})
	assert.NoError(t, err)

	// Update response types
	err = UpdateClient(created.ClientID, ClientUpdateRequest{
		ResponseTypes: []string{"code", "token"},
	})
	assert.NoError(t, err)

	updated, err := ClientByClientID(created.ClientID)
	assert.NoError(t, err)
	assert.Equal(t, []string{"code", "token"}, updated.GetResponseTypes())
}

func TestUpdateClient_TokenEndpointAuthMethod(t *testing.T) {
	testutils.WithTestDB(t)

	// Create a client
	created, err := CreateClient(ClientCreateRequest{
		ClientName:   "Original Name",
		RedirectURIs: []string{"http://localhost:3000/callback"},
	})
	assert.NoError(t, err)

	// Update token endpoint auth method
	err = UpdateClient(created.ClientID, ClientUpdateRequest{
		TokenEndpointAuthMethod: "client_secret_post",
	})
	assert.NoError(t, err)

	updated, err := ClientByClientID(created.ClientID)
	assert.NoError(t, err)
	assert.Equal(t, "client_secret_post", updated.TokenEndpointAuthMethod)
}
