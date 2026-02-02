package client

import (
	"testing"

	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
)

func TestCreateClient(t *testing.T) {
	testutils.WithTestDB(t)

	request := ClientCreateRequest{
		ClientName:   "Test App",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		ClientType:   "confidential",
	}

	response, err := CreateClient(request)
	assert.NoError(t, err)
	assert.NotEmpty(t, response.ClientID)
	assert.NotEmpty(t, response.ClientSecret)
	assert.Equal(t, "Test App", response.ClientName)
	assert.Equal(t, "confidential", response.ClientType)
	assert.Equal(t, []string{"http://localhost:3000/callback"}, response.RedirectURIs)
	assert.Equal(t, []string{"authorization_code", "refresh_token"}, response.GrantTypes)
	assert.Equal(t, "client_secret_basic", response.TokenEndpointAuthMethod)
}

func TestCreatePublicClient(t *testing.T) {
	testutils.WithTestDB(t)

	request := ClientCreateRequest{
		ClientName:   "Public App",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		ClientType:   "public",
	}

	response, err := CreateClient(request)
	assert.NoError(t, err)
	assert.NotEmpty(t, response.ClientID)
	assert.Empty(t, response.ClientSecret)
	assert.Equal(t, "Public App", response.ClientName)
	assert.Equal(t, "public", response.ClientType)
	assert.Equal(t, "none", response.TokenEndpointAuthMethod)
}

func TestCreateClient_Defaults(t *testing.T) {
	testutils.WithTestDB(t)

	// Only provide required fields
	request := ClientCreateRequest{
		ClientName:   "Minimal App",
		RedirectURIs: []string{"http://localhost/callback"},
	}

	response, err := CreateClient(request)
	assert.NoError(t, err)

	// Check defaults are applied
	assert.Equal(t, "confidential", response.ClientType)
	assert.Equal(t, []string{"authorization_code"}, response.GrantTypes)
	assert.Equal(t, []string{"code"}, response.ResponseTypes)
	assert.Equal(t, "openid profile email", response.Scopes)
	assert.Equal(t, "client_secret_basic", response.TokenEndpointAuthMethod)
}
