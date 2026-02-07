package client

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
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

func TestAuthenticateClient_InactiveClient(t *testing.T) {
	testutils.WithTestDB(t)

	// Create a client and then deactivate it
	request := ClientCreateRequest{
		ClientName:   "Inactive App",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		ClientType:   "public",
	}

	created, err := CreateClient(request)
	assert.NoError(t, err)

	// Deactivate the client
	_, err = db.GetDB().Exec(`UPDATE clients SET is_active = FALSE WHERE client_id = ?`, created.ClientID)
	assert.NoError(t, err)

	// Attempt to authenticate
	_, err = AuthenticateClient(created.ClientID, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "inactive")
}

func TestAuthenticateClient_ConfidentialMissingSecret(t *testing.T) {
	testutils.WithTestDB(t)

	request := ClientCreateRequest{
		ClientName:   "Confidential App",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		ClientType:   "confidential",
	}

	created, err := CreateClient(request)
	assert.NoError(t, err)

	// Try to authenticate without providing secret
	_, err = AuthenticateClient(created.ClientID, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "secret required")
}

func TestAuthenticateClientFromRequest_BasicAuth(t *testing.T) {
	testutils.WithTestDB(t)

	// Create a confidential client
	request := ClientCreateRequest{
		ClientName:   "Basic Auth App",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		ClientType:   "confidential",
	}

	created, err := CreateClient(request)
	assert.NoError(t, err)

	// Create request with Basic Auth
	req := httptest.NewRequest("POST", "/oauth2/token", nil)
	req.SetBasicAuth(created.ClientID, created.ClientSecret)

	client, err := AuthenticateClientFromRequest(req)
	assert.NoError(t, err)
	assert.NotNil(t, client)
	assert.Equal(t, created.ClientID, client.ClientID)
}

func TestAuthenticateClientFromRequest_FormParams(t *testing.T) {
	testutils.WithTestDB(t)

	// Create a confidential client
	request := ClientCreateRequest{
		ClientName:   "Form Auth App",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		ClientType:   "confidential",
	}

	created, err := CreateClient(request)
	assert.NoError(t, err)

	// Create request with form params
	form := strings.NewReader("client_id=" + created.ClientID + "&client_secret=" + created.ClientSecret)
	req := httptest.NewRequest("POST", "/oauth2/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client, err := AuthenticateClientFromRequest(req)
	assert.NoError(t, err)
	assert.NotNil(t, client)
	assert.Equal(t, created.ClientID, client.ClientID)
}

func TestAuthenticateClientFromRequest_PublicClient(t *testing.T) {
	testutils.WithTestDB(t)

	// Create a public client
	request := ClientCreateRequest{
		ClientName:   "Public Form App",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		ClientType:   "public",
	}

	created, err := CreateClient(request)
	assert.NoError(t, err)

	// Create request with only client_id (no secret for public client)
	form := strings.NewReader("client_id=" + created.ClientID)
	req := httptest.NewRequest("POST", "/oauth2/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client, err := AuthenticateClientFromRequest(req)
	assert.NoError(t, err)
	assert.NotNil(t, client)
	assert.Equal(t, created.ClientID, client.ClientID)
}

func TestAuthenticateClientFromRequest_NoCredentials(t *testing.T) {
	testutils.WithTestDB(t)

	// Create request without any credentials
	req := httptest.NewRequest("POST", "/oauth2/token", nil)

	client, err := AuthenticateClientFromRequest(req)
	assert.NoError(t, err)
	assert.Nil(t, client)
}

func TestAuthenticateClientFromRequest_NonexistentClient(t *testing.T) {
	testutils.WithTestDB(t)

	// Create request with nonexistent client_id
	form := strings.NewReader("client_id=nonexistent")
	req := httptest.NewRequest("POST", "/oauth2/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Should return nil for backward compatibility
	client, err := AuthenticateClientFromRequest(req)
	assert.NoError(t, err)
	assert.Nil(t, client)
}

func TestIsResponseTypeAllowed(t *testing.T) {
	testutils.WithTestDB(t)

	// Create a client with specific response types
	request := ClientCreateRequest{
		ClientName:    "Test App",
		RedirectURIs:  []string{"http://localhost:3000/callback"},
		ResponseTypes: []string{"code", "token"},
	}

	created, err := CreateClient(request)
	assert.NoError(t, err)

	client, err := ClientByClientID(created.ClientID)
	assert.NoError(t, err)

	// Allowed response types
	assert.True(t, IsResponseTypeAllowed(client, "code"))
	assert.True(t, IsResponseTypeAllowed(client, "token"))

	// Disallowed response type
	assert.False(t, IsResponseTypeAllowed(client, "id_token"))

	// Nil client (backward compatibility)
	assert.True(t, IsResponseTypeAllowed(nil, "id_token"))
}
