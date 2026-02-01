package client

import (
	"testing"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/stretchr/testify/assert"
)

func TestAuthenticateClient(t *testing.T) {
	_, err := db.InitTestDB("../../db/test.db")
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	// Create a confidential client
	request := ClientCreateRequest{
		ClientName:   "Confidential App",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		ClientType:   "confidential",
	}

	created, err := CreateClient(request)
	assert.NoError(t, err)

	// Authenticate with correct credentials
	client, err := AuthenticateClient(created.ClientID, created.ClientSecret)
	assert.NoError(t, err)
	assert.NotNil(t, client)
	assert.Equal(t, created.ClientID, client.ClientID)

	// Authenticate with incorrect credentials
	_, err = AuthenticateClient(created.ClientID, "wrong-secret")
	assert.Error(t, err)

	// Authenticate with nonexistent client
	_, err = AuthenticateClient("nonexistent", "secret")
	assert.Error(t, err)
}

func TestAuthenticatePublicClient(t *testing.T) {
	_, err := db.InitTestDB("../../db/test.db")
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	// Create a public client
	request := ClientCreateRequest{
		ClientName:   "Public App",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		ClientType:   "public",
	}

	created, err := CreateClient(request)
	assert.NoError(t, err)

	// Public clients should authenticate without a secret
	client, err := AuthenticateClient(created.ClientID, "")
	assert.NoError(t, err)
	assert.NotNil(t, client)
}

func TestIsValidRedirectURI(t *testing.T) {
	_, err := db.InitTestDB("../../db/test.db")
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	// Create a client with specific redirect URIs
	request := ClientCreateRequest{
		ClientName:   "Test App",
		RedirectURIs: []string{"http://localhost:3000/callback", "http://example.com/callback"},
	}

	created, err := CreateClient(request)
	assert.NoError(t, err)

	client, err := ClientByClientID(created.ClientID)
	assert.NoError(t, err)

	// Valid redirect URIs
	assert.True(t, IsValidRedirectURI(client, "http://localhost:3000/callback"))
	assert.True(t, IsValidRedirectURI(client, "http://example.com/callback"))

	// Invalid redirect URI
	assert.False(t, IsValidRedirectURI(client, "http://malicious.com/callback"))

	// Nil client (backward compatibility)
	assert.True(t, IsValidRedirectURI(nil, "http://any.com/callback"))
}

func TestIsGrantTypeAllowed(t *testing.T) {
	_, err := db.InitTestDB("../../db/test.db")
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	// Create a client with specific grant types
	request := ClientCreateRequest{
		ClientName:   "Test App",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
	}

	created, err := CreateClient(request)
	assert.NoError(t, err)

	client, err := ClientByClientID(created.ClientID)
	assert.NoError(t, err)

	// Allowed grant types
	assert.True(t, IsGrantTypeAllowed(client, "authorization_code"))
	assert.True(t, IsGrantTypeAllowed(client, "refresh_token"))

	// Disallowed grant type
	assert.False(t, IsGrantTypeAllowed(client, "password"))

	// Nil client (backward compatibility)
	assert.True(t, IsGrantTypeAllowed(nil, "password"))
}
