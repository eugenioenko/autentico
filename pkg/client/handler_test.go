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
	_, err := db.InitTestDB("../../db/test.db")
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

func TestHandleRegisterInvalidMethod(t *testing.T) {
	_, err := db.InitTestDB("../../db/test.db")
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	req := httptest.NewRequest(http.MethodGet, "/oauth2/register", nil)
	rr := httptest.NewRecorder()

	HandleRegister(rr, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}

func TestHandleRegisterInvalidJSON(t *testing.T) {
	_, err := db.InitTestDB("../../db/test.db")
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
	_, err := db.InitTestDB("../../db/test.db")
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
	_, err := db.InitTestDB("../../db/test.db")
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	// Create a client first
	created, err := CreateClient(ClientCreateRequest{
		ClientName:   "Test App",
		RedirectURIs: []string{"http://localhost:3000/callback"},
	})
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/register/"+created.ClientID, nil)
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
	_, err := db.InitTestDB("../../db/test.db")
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	req := httptest.NewRequest(http.MethodGet, "/oauth2/register/nonexistent", nil)
	rr := httptest.NewRecorder()

	HandleGetClient(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandleUpdateClient(t *testing.T) {
	_, err := db.InitTestDB("../../db/test.db")
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	// Create a client first
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
	rr := httptest.NewRecorder()

	HandleUpdateClient(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var response ClientInfoResponse
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "Updated Name", response.ClientName)
}

func TestHandleDeleteClient(t *testing.T) {
	_, err := db.InitTestDB("../../db/test.db")
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	// Create a client first
	created, err := CreateClient(ClientCreateRequest{
		ClientName:   "To Be Deleted",
		RedirectURIs: []string{"http://localhost:3000/callback"},
	})
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodDelete, "/oauth2/register/"+created.ClientID, nil)
	rr := httptest.NewRecorder()

	HandleDeleteClient(rr, req)

	assert.Equal(t, http.StatusNoContent, rr.Code)

	// Verify client is deactivated
	client, err := ClientByClientID(created.ClientID)
	assert.NoError(t, err)
	assert.False(t, client.IsActive)
}

func TestHandleListClients(t *testing.T) {
	_, err := db.InitTestDB("../../db/test.db")
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	// Create some clients
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

func TestHandleClientEndpoint(t *testing.T) {
	_, err := db.InitTestDB("../../db/test.db")
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	// Test POST to /oauth2/register (create client)
	reqBody := ClientCreateRequest{
		ClientName:   "Test App",
		RedirectURIs: []string{"http://localhost:3000/callback"},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	HandleClientEndpoint(rr, req)

	assert.Equal(t, http.StatusCreated, rr.Code)

	var response ClientResponse
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)

	// Test GET to /oauth2/register/{client_id}
	req = httptest.NewRequest(http.MethodGet, "/oauth2/register/"+response.ClientID, nil)
	rr = httptest.NewRecorder()

	HandleClientEndpoint(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestExtractClientIDFromPath(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"/oauth2/register", ""},
		{"/oauth2/register/", ""},
		{"/oauth2/register/abc123", "abc123"},
		{"/oauth2/register/abc123/", "abc123"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := extractClientIDFromPath(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHandleRegisterInvalidRedirectURI(t *testing.T) {
	_, err := db.InitTestDB("../../db/test.db")
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
	_, err := db.InitTestDB("../../db/test.db")
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
	rr := httptest.NewRecorder()

	HandleUpdateClient(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandleDeleteClientNotFound(t *testing.T) {
	_, err := db.InitTestDB("../../db/test.db")
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	req := httptest.NewRequest(http.MethodDelete, "/oauth2/register/nonexistent", nil)
	rr := httptest.NewRecorder()

	HandleDeleteClient(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandleListClientsEmpty(t *testing.T) {
	_, err := db.InitTestDB("../../db/test.db")
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	req := httptest.NewRequest(http.MethodGet, "/oauth2/register", nil)
	rr := httptest.NewRecorder()

	HandleListClients(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	// Should return empty array, not null
	var response []*ClientInfoResponse
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Empty(t, response)
}
