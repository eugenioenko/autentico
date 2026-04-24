package federation

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
)

func TestHandleFederationProviders(t *testing.T) {
	testutils.WithTestDB(t)

	// Create a provider
	reqBody := FederationProviderRequest{
		ID:           "p1",
		Name:         "Provider 1",
		Issuer:       "https://iss1.com",
		ClientID:     "c1",
		ClientSecret: "s1",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/admin/api/federation", bytes.NewBuffer(body))
	rr := httptest.NewRecorder()
	HandleCreateProvider(rr, req)
	assert.Equal(t, http.StatusCreated, rr.Code)

	// List providers
	req = httptest.NewRequest(http.MethodGet, "/admin/api/federation", nil)
	rr = httptest.NewRecorder()
	HandleListProviders(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	var listResp struct {
		Data struct {
			Items []map[string]any `json:"items"`
			Total int              `json:"total"`
		} `json:"data"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &listResp)
	assert.Equal(t, 1, listResp.Data.Total)
	assert.Len(t, listResp.Data.Items, 1)
	assert.Equal(t, "p1", listResp.Data.Items[0]["id"])

	// Get provider
	req = httptest.NewRequest(http.MethodGet, "/admin/api/federation/p1", nil)
	req.SetPathValue("id", "p1")
	rr = httptest.NewRecorder()
	HandleGetProvider(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	var p map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &p)
	assert.Equal(t, "Provider 1", p["name"])

	// Update provider
	updateReq := FederationProviderRequest{
		Name:     "Updated Name",
		Issuer:   "https://iss1.com",
		ClientID: "c1",
	}
	body, _ = json.Marshal(updateReq)
	req = httptest.NewRequest(http.MethodPut, "/admin/api/federation/p1", bytes.NewBuffer(body))
	req.SetPathValue("id", "p1")
	rr = httptest.NewRecorder()
	HandleUpdateProvider(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	// Delete provider
	req = httptest.NewRequest(http.MethodDelete, "/admin/api/federation/p1", nil)
	req.SetPathValue("id", "p1")
	rr = httptest.NewRecorder()
	HandleDeleteProvider(rr, req)
	assert.Equal(t, http.StatusNoContent, rr.Code)

	// Verify deleted
	req = httptest.NewRequest(http.MethodGet, "/admin/api/federation/p1", nil)
	req.SetPathValue("id", "p1")
	rr = httptest.NewRecorder()
	HandleGetProvider(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandleFederationProviders_Errors(t *testing.T) {
	testutils.WithTestDB(t)

	// Get non-existent
	req := httptest.NewRequest(http.MethodGet, "/admin/api/federation/nonexistent", nil)
	req.SetPathValue("id", "nonexistent")
	rr := httptest.NewRecorder()
	HandleGetProvider(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)

	// Invalid JSON on create
	req = httptest.NewRequest(http.MethodPost, "/admin/api/federation", bytes.NewBufferString("{invalid"))
	rr = httptest.NewRecorder()
	HandleCreateProvider(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	// Missing fields on create
	req = httptest.NewRequest(http.MethodPost, "/admin/api/federation", bytes.NewBufferString("{}"))
	rr = httptest.NewRecorder()
	HandleCreateProvider(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	// Create p1 for update error tests
	_ = CreateFederationProvider(FederationProvider{
		ID:           "p1",
		Name:         "P1",
		Issuer:       "https://iss.com",
		ClientID:     "c1",
		ClientSecret: "s1",
		Enabled:      true,
	})

	// Invalid JSON on update
	req = httptest.NewRequest(http.MethodPut, "/admin/api/federation/p1", bytes.NewBufferString("{invalid"))
	req.SetPathValue("id", "p1")
	rr = httptest.NewRecorder()
	HandleUpdateProvider(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	// Update non-existent
	req = httptest.NewRequest(http.MethodPut, "/admin/api/federation/nope", bytes.NewBufferString("{}"))
	req.SetPathValue("id", "nope")
	rr = httptest.NewRecorder()
	HandleUpdateProvider(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)

	// Delete non-existent
	req = httptest.NewRequest(http.MethodDelete, "/admin/api/federation/nope", nil)
	req.SetPathValue("id", "nope")
	rr = httptest.NewRecorder()
	HandleDeleteProvider(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}
