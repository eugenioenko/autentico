package client

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/stretchr/testify/assert"
)

func TestHandleRegister(t *testing.T) {
	_, err := db.InitTestDB()
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	reqBody := ClientCreateRequest{
		ClientName:   "Test App",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		GrantTypes:   []string{"authorization_code"},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	HandleRegister(rr, req)

	assert.Equal(t, http.StatusCreated, rr.Code)

	var response ClientResponse
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.NotEmpty(t, response.ClientID)
	assert.NotEmpty(t, response.ClientSecret)
	assert.Equal(t, "Test App", response.ClientName)
}

func TestHandleRegisterInvalidJSON(t *testing.T) {
	_, err := db.InitTestDB()
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	req := httptest.NewRequest(http.MethodPost, "/oauth2/register", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	HandleRegister(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleRegisterMissingFields(t *testing.T) {
	_, err := db.InitTestDB()
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	reqBody := ClientCreateRequest{
		ClientName: "Test App",
		// Missing redirect_uris
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	HandleRegister(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleGetClient(t *testing.T) {
	_, err := db.InitTestDB()
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	created, err := CreateClient(ClientCreateRequest{
		ClientName:   "Test App",
		RedirectURIs: []string{"http://localhost:3000/callback"},
	})
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/register/"+created.ClientID, nil)
	req.SetPathValue("client_id", created.ClientID)
	rr := httptest.NewRecorder()

	HandleGetClient(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var response ClientInfoResponse
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, created.ClientID, response.ClientID)
	assert.Equal(t, "Test App", response.ClientName)
}

func TestHandleGetClientNotFound(t *testing.T) {
	_, err := db.InitTestDB()
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	req := httptest.NewRequest(http.MethodGet, "/oauth2/register/nonexistent", nil)
	req.SetPathValue("client_id", "nonexistent")
	rr := httptest.NewRecorder()

	HandleGetClient(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandleUpdateClient(t *testing.T) {
	_, err := db.InitTestDB()
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	created, err := CreateClient(ClientCreateRequest{
		ClientName:   "Original Name",
		RedirectURIs: []string{"http://localhost:3000/callback"},
	})
	assert.NoError(t, err)

	reqBody := ClientUpdateRequest{
		ClientName: "Updated Name",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPut, "/oauth2/register/"+created.ClientID, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("client_id", created.ClientID)
	rr := httptest.NewRecorder()

	HandleUpdateClient(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var response ClientInfoResponse
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "Updated Name", response.ClientName)
}

func TestHandleDeleteClient(t *testing.T) {
	_, err := db.InitTestDB()
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	created, err := CreateClient(ClientCreateRequest{
		ClientName:   "To Be Deleted",
		RedirectURIs: []string{"http://localhost:3000/callback"},
	})
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodDelete, "/oauth2/register/"+created.ClientID, nil)
	req.SetPathValue("client_id", created.ClientID)
	rr := httptest.NewRecorder()

	HandleDeleteClient(rr, req)

	assert.Equal(t, http.StatusNoContent, rr.Code)

	client, err := ClientByClientID(created.ClientID)
	assert.NoError(t, err)
	assert.False(t, client.IsActive)
}

func TestHandleListClients(t *testing.T) {
	_, err := db.InitTestDB()
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	_, err = CreateClient(ClientCreateRequest{
		ClientName:   "App 1",
		RedirectURIs: []string{"http://localhost:3001/callback"},
	})
	assert.NoError(t, err)

	_, err = CreateClient(ClientCreateRequest{
		ClientName:   "App 2",
		RedirectURIs: []string{"http://localhost:3002/callback"},
	})
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/register", nil)
	rr := httptest.NewRecorder()

	HandleListClients(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var response []*ClientInfoResponse
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Len(t, response, 2)
}

func TestHandleListClientsEmpty(t *testing.T) {
	_, err := db.InitTestDB()
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	req := httptest.NewRequest(http.MethodGet, "/oauth2/register", nil)
	rr := httptest.NewRecorder()

	HandleListClients(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var response []*ClientInfoResponse
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Empty(t, response)
}

func TestHandleRegisterInvalidRedirectURI(t *testing.T) {
	_, err := db.InitTestDB()
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	reqBody := ClientCreateRequest{
		ClientName:   "Test App",
		RedirectURIs: []string{"not-a-valid-uri"},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	HandleRegister(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid redirect URI")
}

func TestHandleUpdateClientNotFound(t *testing.T) {
	_, err := db.InitTestDB()
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	reqBody := ClientUpdateRequest{
		ClientName: "Updated Name",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPut, "/oauth2/register/nonexistent", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("client_id", "nonexistent")
	rr := httptest.NewRecorder()

	HandleUpdateClient(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandleDeleteClientNotFound(t *testing.T) {
	_, err := db.InitTestDB()
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	req := httptest.NewRequest(http.MethodDelete, "/oauth2/register/nonexistent", nil)
	req.SetPathValue("client_id", "nonexistent")
	rr := httptest.NewRecorder()

	HandleDeleteClient(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandleUpdateClient_InvalidJSON(t *testing.T) {
	_, err := db.InitTestDB()
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	req := httptest.NewRequest(http.MethodPut, "/oauth2/register/some-id", bytes.NewReader([]byte("not json")))
	req.SetPathValue("client_id", "some-id")
	rr := httptest.NewRecorder()
	HandleUpdateClient(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid JSON payload")
}

func TestHandleUpdateClient_InvalidRedirectURIs(t *testing.T) {
	_, err := db.InitTestDB()
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	created, err := CreateClient(ClientCreateRequest{
		ClientName:   "Test App",
		RedirectURIs: []string{"http://localhost:3000/callback"},
	})
	assert.NoError(t, err)

	reqBody := ClientUpdateRequest{
		ClientName:   "Updated",
		RedirectURIs: []string{"not-a-valid-uri"},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPut, "/oauth2/register/"+created.ClientID, bytes.NewReader(body))
	req.SetPathValue("client_id", created.ClientID)
	rr := httptest.NewRecorder()
	HandleUpdateClient(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid redirect URI")
}

// --- RFC 7591 compliance tests ---

func TestHandleRegister_RFC7591_UnknownFieldsIgnored(t *testing.T) {
	// RFC 7591 §2: The server MUST ignore any client metadata it does not understand.
	_, err := db.InitTestDB()
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	// Send registration with extra unknown fields (logo_uri, contacts, etc.)
	rawJSON := `{
		"client_name": "Test App With Extras",
		"redirect_uris": ["http://localhost:3000/callback"],
		"logo_uri": "https://example.com/logo.png",
		"contacts": ["admin@example.com"],
		"tos_uri": "https://example.com/tos",
		"policy_uri": "https://example.com/policy",
		"software_id": "some-uuid-value"
	}`

	req := httptest.NewRequest(http.MethodPost, "/oauth2/register", bytes.NewReader([]byte(rawJSON)))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	HandleRegister(rr, req)

	assert.Equal(t, http.StatusCreated, rr.Code, "unknown fields must be silently ignored, not rejected")
	var response ClientResponse
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "Test App With Extras", response.ClientName)
}

func TestHandleRegister_RFC7591_InvalidMetadata_ErrorCode(t *testing.T) {
	// RFC 7591 §3.2.2: invalid_client_metadata when a metadata field value is invalid.
	_, err := db.InitTestDB()
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	reqBody := ClientCreateRequest{
		ClientName:   "Bad Grant Client",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		GrantTypes:   []string{"unsupported_grant"},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	HandleRegister(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), `"invalid_client_metadata"`)
}

func TestHandleRegister_RFC7591_InvalidRedirectURI_ErrorCode(t *testing.T) {
	// RFC 7591 §3.2.2: invalid_redirect_uri when redirect URI values are invalid.
	_, err := db.InitTestDB()
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	reqBody := ClientCreateRequest{
		ClientName:   "Bad URI Client",
		RedirectURIs: []string{"not-a-valid-uri"},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	HandleRegister(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), `"invalid_redirect_uri"`)
}

func TestHandleRegister_RFC7591_ResponseContainsAllFields(t *testing.T) {
	// RFC 7591 §3.2.1: The server MUST return all registered metadata,
	// including client_id (REQUIRED), client_secret_expires_at (REQUIRED if secret issued),
	// and client_id_issued_at (OPTIONAL).
	_, err := db.InitTestDB()
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	reqBody := ClientCreateRequest{
		ClientName:   "Full Response Client",
		RedirectURIs: []string{"http://localhost:3000/callback"},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	HandleRegister(rr, req)

	assert.Equal(t, http.StatusCreated, rr.Code)

	// Parse as raw map to check field presence
	var raw map[string]interface{}
	err = json.Unmarshal(rr.Body.Bytes(), &raw)
	assert.NoError(t, err)

	// RFC 7591 §3.2.1: REQUIRED fields
	assert.Contains(t, raw, "client_id")
	assert.Contains(t, raw, "client_secret")
	assert.Contains(t, raw, "client_secret_expires_at")
	assert.Contains(t, raw, "client_id_issued_at")

	// All registered metadata
	assert.Contains(t, raw, "client_name")
	assert.Contains(t, raw, "client_type")
	assert.Contains(t, raw, "redirect_uris")
	assert.Contains(t, raw, "grant_types")
	assert.Contains(t, raw, "response_types")
	assert.Contains(t, raw, "scopes")
	assert.Contains(t, raw, "token_endpoint_auth_method")

	// client_id_issued_at should be a reasonable Unix timestamp (> 0)
	issuedAt, ok := raw["client_id_issued_at"].(float64)
	assert.True(t, ok, "client_id_issued_at should be a number")
	assert.Greater(t, issuedAt, float64(0), "client_id_issued_at should be > 0")
}

func TestHandleRegister_RFC7591_PublicClient_NoSecret(t *testing.T) {
	// RFC 7591 §3.2.1: client_secret is OPTIONAL — not issued for public clients.
	_, err := db.InitTestDB()
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	reqBody := ClientCreateRequest{
		ClientName:   "Public App",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		ClientType:   "public",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	HandleRegister(rr, req)

	assert.Equal(t, http.StatusCreated, rr.Code)

	var response ClientResponse
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Empty(t, response.ClientSecret, "public client should not receive a secret")
	assert.Equal(t, "none", response.TokenEndpointAuthMethod)
}

func TestHandleUpdateClient_RFC7591_InvalidMetadata_ErrorCode(t *testing.T) {
	// RFC 7591 §3.2.2: invalid_client_metadata on update validation failure.
	_, err := db.InitTestDB()
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	created, err := CreateClient(ClientCreateRequest{
		ClientName:   "Test App",
		RedirectURIs: []string{"http://localhost:3000/callback"},
	})
	assert.NoError(t, err)

	reqBody := ClientUpdateRequest{
		GrantTypes: []string{"unsupported_grant"},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPut, "/oauth2/register/"+created.ClientID, bytes.NewReader(body))
	req.SetPathValue("client_id", created.ClientID)
	rr := httptest.NewRecorder()
	HandleUpdateClient(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), `"invalid_client_metadata"`)
}

func TestHandleUpdateClient_RFC7591_InvalidRedirectURI_ErrorCode(t *testing.T) {
	// RFC 7591 §3.2.2: invalid_redirect_uri on update with bad redirect URI.
	_, err := db.InitTestDB()
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	created, err := CreateClient(ClientCreateRequest{
		ClientName:   "Test App",
		RedirectURIs: []string{"http://localhost:3000/callback"},
	})
	assert.NoError(t, err)

	reqBody := ClientUpdateRequest{
		RedirectURIs: []string{"not-a-valid-uri"},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPut, "/oauth2/register/"+created.ClientID, bytes.NewReader(body))
	req.SetPathValue("client_id", created.ClientID)
	rr := httptest.NewRecorder()
	HandleUpdateClient(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), `"invalid_redirect_uri"`)
}
