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

func TestHandleAdminFederationEndpoint(t *testing.T) {
	testutils.WithTestDB(t)

	// 1. Create a provider
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
	HandleAdminFederationEndpoint(rr, req)
	assert.Equal(t, http.StatusCreated, rr.Code)

	// 2. List providers
	req = httptest.NewRequest(http.MethodGet, "/admin/api/federation", nil)
	rr = httptest.NewRecorder()
	HandleAdminFederationEndpoint(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	var list []map[string]any
	json.Unmarshal(rr.Body.Bytes(), &list)
	assert.Len(t, list, 1)
	assert.Equal(t, "p1", list[0]["id"])

	// 3. Get provider
	req = httptest.NewRequest(http.MethodGet, "/admin/api/federation/p1", nil)
	rr = httptest.NewRecorder()
	HandleAdminFederationEndpoint(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	var p map[string]any
	json.Unmarshal(rr.Body.Bytes(), &p)
	assert.Equal(t, "Provider 1", p["name"])

	// 4. Update provider
	updateReq := FederationProviderRequest{
		Name:     "Updated Name",
		Issuer:   "https://iss1.com",
		ClientID: "c1",
	}
	body, _ = json.Marshal(updateReq)
	req = httptest.NewRequest(http.MethodPut, "/admin/api/federation/p1", bytes.NewBuffer(body))
	rr = httptest.NewRecorder()
	HandleAdminFederationEndpoint(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	// 5. Delete provider
	req = httptest.NewRequest(http.MethodDelete, "/admin/api/federation/p1", nil)
	rr = httptest.NewRecorder()
	HandleAdminFederationEndpoint(rr, req)
	assert.Equal(t, http.StatusNoContent, rr.Code)

	// 6. Verify deleted
	req = httptest.NewRequest(http.MethodGet, "/admin/api/federation/p1", nil)
	rr = httptest.NewRecorder()
	HandleAdminFederationEndpoint(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandleAdminFederationEndpoint_Errors(t *testing.T) {
	testutils.WithTestDB(t)

	// Method not allowed on base endpoint
	req := httptest.NewRequest(http.MethodPatch, "/admin/api/federation", nil)
	rr := httptest.NewRecorder()
	HandleAdminFederationEndpoint(rr, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)

	// Invalid ID
	req = httptest.NewRequest(http.MethodGet, "/admin/api/federation/nonexistent", nil)
	rr = httptest.NewRecorder()
	HandleAdminFederationEndpoint(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)

	// Invalid JSON on create
	req = httptest.NewRequest(http.MethodPost, "/admin/api/federation", bytes.NewBufferString("{invalid"))
	rr = httptest.NewRecorder()
	HandleAdminFederationEndpoint(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	// Missing fields on create
	req = httptest.NewRequest(http.MethodPost, "/admin/api/federation", bytes.NewBufferString("{}"))
	rr = httptest.NewRecorder()
	HandleAdminFederationEndpoint(rr, req)
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
	rr = httptest.NewRecorder()
	HandleAdminFederationEndpoint(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	// Method not allowed on specific provider
	req = httptest.NewRequest(http.MethodPost, "/admin/api/federation/p1", nil)
	rr = httptest.NewRecorder()
	HandleAdminFederationEndpoint(rr, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}
