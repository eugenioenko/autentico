package client

import (
	"testing"

	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
)

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
	updated, err := UpdateClient(created.ClientID, ClientUpdateRequest{
		ClientName: "Updated Name",
	})
	assert.NoError(t, err)
	assert.Equal(t, "Updated Name", updated.ClientName)
	// Original values should be preserved
	assert.Equal(t, []string{"http://localhost:3000/callback"}, updated.RedirectURIs)
	assert.Equal(t, []string{"authorization_code"}, updated.GrantTypes)
}

func TestUpdateClient_NotFound(t *testing.T) {
	testutils.WithTestDB(t)

	_, err := UpdateClient("nonexistent", ClientUpdateRequest{
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
	updated, err := UpdateClient(created.ClientID, ClientUpdateRequest{
		ClientName:   "New Name",
		RedirectURIs: []string{"http://newhost.com/callback"},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		Scopes:       "openid profile email",
		IsActive:     &isActive,
	})
	assert.NoError(t, err)
	assert.Equal(t, "New Name", updated.ClientName)
	assert.Equal(t, []string{"http://newhost.com/callback"}, updated.RedirectURIs)
	assert.Equal(t, []string{"authorization_code", "refresh_token"}, updated.GrantTypes)
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
	updated, err := UpdateClient(created.ClientID, ClientUpdateRequest{
		ResponseTypes: []string{"code", "token"},
	})
	assert.NoError(t, err)
	assert.Equal(t, []string{"code", "token"}, updated.ResponseTypes)
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
	updated, err := UpdateClient(created.ClientID, ClientUpdateRequest{
		TokenEndpointAuthMethod: "client_secret_post",
	})
	assert.NoError(t, err)
	assert.Equal(t, "client_secret_post", updated.TokenEndpointAuthMethod)
}
