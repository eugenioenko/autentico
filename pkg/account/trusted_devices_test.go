package account

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/trusteddevice"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
)

func TestHandleListTrustedDevices(t *testing.T) {
	testutils.WithTestDB(t)
	token, usr := setupTestUserAndSession(t)

	_ = trusteddevice.CreateTrustedDevice(trusteddevice.TrustedDevice{
		ID:         "td1",
		UserID:     usr.ID,
		DeviceName: "My Browser",
		ExpiresAt:  time.Now().Add(time.Hour),
	})

	rr := testutils.MockApiRequestWithAuth(t, "", "GET", "/account/api/trusted-devices", HandleListTrustedDevices, token)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHandleRevokeTrustedDevice(t *testing.T) {
	testutils.WithTestDB(t)
	token, usr := setupTestUserAndSession(t)

	_ = trusteddevice.CreateTrustedDevice(trusteddevice.TrustedDevice{
		ID:         "td1",
		UserID:     usr.ID,
		DeviceName: "My Browser",
		ExpiresAt:  time.Now().Add(time.Hour),
	})

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /account/api/trusted-devices/{id}", HandleRevokeTrustedDevice)

	req := httptest.NewRequest("DELETE", "/account/api/trusted-devices/td1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	// Not owned
	req = httptest.NewRequest("DELETE", "/account/api/trusted-devices/other", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestHandleRevokeTrustedDevice_MissingID(t *testing.T) {
	testutils.WithTestDB(t)
	token, _ := setupTestUserAndSession(t)

	req := httptest.NewRequest("DELETE", "/account/api/trusted-devices/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	HandleRevokeTrustedDevice(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleRevokeTrustedDevice_Extra(t *testing.T) {
	testutils.WithTestDB(t)
	token, _ := setupTestUserAndSession(t)

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /account/api/trusted-devices/{id}", HandleRevokeTrustedDevice)

	// Revoke nonexistent
	req := httptest.NewRequest("DELETE", "/account/api/trusted-devices/none", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	
	assert.Equal(t, http.StatusForbidden, rr.Code)
}
