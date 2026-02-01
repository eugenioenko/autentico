package client

import (
	"testing"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/stretchr/testify/assert"
)

func TestCreateClient(t *testing.T) {
	_, err := db.InitTestDB("../../db/test.db")
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

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
	_, err := db.InitTestDB("../../db/test.db")
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

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
