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
	_, err := db.InitTestDB()
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
	_, err := db.InitTestDB()
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
	_, err := db.InitTestDB()
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

func TestIsValidRedirectURIWildcard(t *testing.T) {
	_, err := db.InitTestDB()
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	request := ClientCreateRequest{
		ClientName:   "Wildcard App",
		RedirectURIs: []string{"https://localhost.emobix.co.uk:8443/*", "http://exact.com/callback"},
	}

	created, err := CreateClient(request)
	assert.NoError(t, err)

	client, err := ClientByClientID(created.ClientID)
	assert.NoError(t, err)

	// /* wildcard: suffix is empty so HasSuffix("") is always true — matches any path under prefix
	assert.True(t, IsValidRedirectURI(client, "https://localhost.emobix.co.uk:8443/test/abc123/callback"))
	assert.True(t, IsValidRedirectURI(client, "https://localhost.emobix.co.uk:8443/test/a/autentico/callback"))
	assert.True(t, IsValidRedirectURI(client, "https://localhost.emobix.co.uk:8443/anything"))

	// Exact match still works alongside wildcard
	assert.True(t, IsValidRedirectURI(client, "http://exact.com/callback"))

	// Different host does not match the wildcard
	assert.False(t, IsValidRedirectURI(client, "https://evil.com/test/abc123/callback"))
	assert.False(t, IsValidRedirectURI(client, "https://localhost.emobix.co.uk:9999/test/abc/callback"))
}

func TestIsValidRedirectURIWildcard_SuffixCheck(t *testing.T) {
	_, err := db.InitTestDB()
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	// Pattern: /test/*/callback — wildcard mid-path with suffix
	request := ClientCreateRequest{
		ClientName:   "Mid Wildcard App",
		RedirectURIs: []string{"https://example.com/test/*/callback"},
	}
	created, err := CreateClient(request)
	assert.NoError(t, err)
	client, err := ClientByClientID(created.ClientID)
	assert.NoError(t, err)

	// Must match: prefix and suffix both present
	assert.True(t, IsValidRedirectURI(client, "https://example.com/test/abc123/callback"))
	assert.True(t, IsValidRedirectURI(client, "https://example.com/test/a/plan/callback"))

	// Must reject: extra path after the suffix (oidcc-ensure-registered-redirect-uri scenario)
	assert.False(t, IsValidRedirectURI(client, "https://example.com/test/abc123/callback/extra"))
	assert.False(t, IsValidRedirectURI(client, "https://example.com/test/abc123/callback/2FCOzETCNZ"))

	// Must reject: different host
	assert.False(t, IsValidRedirectURI(client, "https://evil.com/test/abc123/callback"))
}

// oidcc-ensure-registered-redirect-uri: exact URI registered, path extension must be rejected
func TestIsValidRedirectURI_ExactMatch_RejectsPathExtension(t *testing.T) {
	_, err := db.InitTestDB()
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	request := ClientCreateRequest{
		ClientName:   "Exact URI App",
		RedirectURIs: []string{"https://localhost.emobix.co.uk:8443/test/a/plan123/callback"},
	}
	created, err := CreateClient(request)
	assert.NoError(t, err)

	client, err := ClientByClientID(created.ClientID)
	assert.NoError(t, err)

	// Registered URI must match exactly
	assert.True(t, IsValidRedirectURI(client, "https://localhost.emobix.co.uk:8443/test/a/plan123/callback"))

	// Path extension must be rejected (the oidcc-ensure-registered-redirect-uri test case)
	assert.False(t, IsValidRedirectURI(client, "https://localhost.emobix.co.uk:8443/test/a/plan123/callback/extra"))
	assert.False(t, IsValidRedirectURI(client, "https://localhost.emobix.co.uk:8443/test/a/plan123/callback/2FCOzETCNZ"))
}

func TestIsGrantTypeAllowed(t *testing.T) {
	_, err := db.InitTestDB()
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
	assert.Contains(t, err.Error(), "invalid client credentials")
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

	// Should return an error when client_id is provided but not registered
	client, err := AuthenticateClientFromRequest(req)
	assert.Error(t, err)
	assert.Nil(t, client)
}

func TestValidateScopes(t *testing.T) {
	c := &Client{Scopes: "openid profile email"}

	// Subset of allowed scopes
	assert.True(t, ValidateScopes(c, "openid"))
	assert.True(t, ValidateScopes(c, "openid profile"))
	assert.True(t, ValidateScopes(c, "openid profile email"))

	// Scope not in the allowed list
	assert.False(t, ValidateScopes(c, "offline_access"))
	assert.False(t, ValidateScopes(c, "openid offline_access"))

	// Empty requested scope is always valid
	assert.True(t, ValidateScopes(c, ""))

	// Nil client — all scopes allowed (backward compatibility)
	assert.True(t, ValidateScopes(nil, "offline_access"))

	// Client with no scopes configured — all scopes allowed
	noScopes := &Client{Scopes: ""}
	assert.True(t, ValidateScopes(noScopes, "offline_access"))
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
