package account

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/federation"
	"github.com/eugenioenko/autentico/pkg/model"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleListConnectedProviders(t *testing.T) {
	testutils.WithTestDB(t)
	token, usr := setupTestUserAndSession(t)

	_, _ = db.GetDB().Exec(`INSERT INTO federation_providers (id, name, issuer, client_id, client_secret) VALUES ('p1', 'Google', 'iss', 'c1', 's1')`)
	_ = federation.CreateFederatedIdentity(federation.FederatedIdentity{ProviderID: "p1", ProviderUserID: "sub1", UserID: usr.ID})

	rr := testutils.MockApiRequestWithAuth(t, "", "GET", "/account/api/connected-providers", HandleListConnectedProviders, token)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHandleListConnectedProviders_Partial(t *testing.T) {
	testutils.WithTestDB(t)
	token, usr := setupTestUserAndSession(t)

	// Provider doesn't exist in federation_providers table
	_ = federation.CreateFederatedIdentity(federation.FederatedIdentity{ProviderID: "nonexistent", ProviderUserID: "sub1", UserID: usr.ID})

	rr := testutils.MockApiRequestWithAuth(t, "", "GET", "/account/api/connected-providers", HandleListConnectedProviders, token)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHandleDisconnectProvider_Success(t *testing.T) {
	testutils.WithTestDB(t)
	token, usr := setupTestUserAndSession(t)

	_, _ = db.GetDB().Exec(`INSERT INTO federation_providers (id, name, issuer, client_id, client_secret) VALUES ('p1', 'Google', 'iss', 'c1', 's1')`)
	_ = federation.CreateFederatedIdentity(federation.FederatedIdentity{ProviderID: "p1", ProviderUserID: "sub1", UserID: usr.ID})
	identities, _ := federation.FederatedIdentitiesByUserID(usr.ID)
	fiID := identities[0].ID

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /account/api/connected-providers/{id}", HandleDisconnectProvider)

	req := httptest.NewRequest("DELETE", "/account/api/connected-providers/"+fiID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	// Not owned
	req = httptest.NewRequest("DELETE", "/account/api/connected-providers/other", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestHandleDisconnectProvider_Lockout(t *testing.T) {
	testutils.WithTestDB(t)
	token, usr := setupTestUserAndSession(t)

	// No password
	_, _ = db.GetDB().Exec("UPDATE users SET password = '' WHERE id = ?", usr.ID)
	
	_, _ = db.GetDB().Exec(`INSERT INTO federation_providers (id, name, issuer, client_id, client_secret) VALUES ('p1', 'Google', 'iss', 'c1', 's1')`)
	_ = federation.CreateFederatedIdentity(federation.FederatedIdentity{ProviderID: "p1", ProviderUserID: "sub1", UserID: usr.ID})
	identities, _ := federation.FederatedIdentitiesByUserID(usr.ID)
	fiID := identities[0].ID

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /account/api/connected-providers/{id}", HandleDisconnectProvider)

	req := httptest.NewRequest("DELETE", "/account/api/connected-providers/"+fiID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "lockout_prevention")
}

func TestHandleDisconnectProvider_InvalidPath(t *testing.T) {
	testutils.WithTestDB(t)
	token, _ := setupTestUserAndSession(t)
	
	req := httptest.NewRequest("DELETE", "/account/api/connected-providers/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	HandleDisconnectProvider(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleDisconnectProvider_MissingID(t *testing.T) {
	testutils.WithTestDB(t)
	token, _ := setupTestUserAndSession(t)

	req := httptest.NewRequest("DELETE", "/account/api/connected-providers/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	HandleDisconnectProvider(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Missing identity ID")
}

func TestHandleDisconnectProvider_Success_Extra(t *testing.T) {
	testutils.WithTestDB(t)
	token, u := setupTestUserAndSession(t)

	// Must create provider first due to FK
	_, err := db.GetDB().Exec(`INSERT INTO federation_providers (id, name, issuer, client_id, client_secret) VALUES ('p1', 'P1', 'http://iss', 'c1', 's1')`)
	assert.NoError(t, err)
	// Create a connected provider
	_, err = db.GetDB().Exec(`INSERT INTO federated_identities (id, provider_id, provider_user_id, user_id, email) VALUES ('fi1', 'p1', 'sub1', ?, 'e1@test.com')`, u.ID)
	assert.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /account/api/connected-providers/{id}", HandleDisconnectProvider)

	req := httptest.NewRequest("DELETE", "/account/api/connected-providers/fi1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHandleListConnectedProviders_Extra(t *testing.T) {
	testutils.WithTestDB(t)
	token, u := setupTestUserAndSession(t)

	// Create provider and identity
	_, _ = db.GetDB().Exec(`INSERT INTO federation_providers (id, name, issuer, client_id, client_secret) VALUES ('p1', 'P1', 'http://iss', 'c1', 's1')`)
	_, _ = db.GetDB().Exec(`INSERT INTO federated_identities (id, provider_id, provider_user_id, user_id, email) VALUES ('fi1', 'p1', 'sub1', ?, 'e1@test.com')`, u.ID)

	req := httptest.NewRequest("GET", "/account/api/connected-providers", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	HandleListConnectedProviders(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var listResp model.ApiResponse[[]ConnectedProviderResponse]
	err := json.Unmarshal(rr.Body.Bytes(), &listResp)
	require.NoError(t, err)
	assert.Len(t, listResp.Data, 1)
	assert.Equal(t, "P1", listResp.Data[0].ProviderName)
}
