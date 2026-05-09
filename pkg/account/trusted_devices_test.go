package account

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/middleware"
	"github.com/eugenioenko/autentico/pkg/trusteddevice"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
)

func TestHandleListTrustedDevices(t *testing.T) {
	testutils.WithTestDB(t)
	_, usr, info := setupTestUserAndSession(t)

	_ = trusteddevice.CreateTrustedDevice(trusteddevice.TrustedDevice{
		ID:         "td1",
		UserID:     usr.ID,
		DeviceName: "My Browser",
		ExpiresAt:  time.Now().Add(time.Hour),
	})

	rr := mockAuthRequest(t, "", "GET", "/account/api/trusted-devices", HandleListTrustedDevices, info)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHandleRevokeTrustedDevice(t *testing.T) {
	testutils.WithTestDB(t)
	_, usr, info := setupTestUserAndSession(t)

	_ = trusteddevice.CreateTrustedDevice(trusteddevice.TrustedDevice{
		ID:         "td1",
		UserID:     usr.ID,
		DeviceName: "My Browser",
		ExpiresAt:  time.Now().Add(time.Hour),
	})

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /account/api/trusted-devices/{id}", HandleRevokeTrustedDevice)

	req := httptest.NewRequest("DELETE", "/account/api/trusted-devices/td1", nil)
	req = middleware.WithAuthInfo(req, info)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	// Not owned
	req = httptest.NewRequest("DELETE", "/account/api/trusted-devices/other", nil)
	req = middleware.WithAuthInfo(req, info)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestHandleRevokeTrustedDevice_MissingID(t *testing.T) {
	testutils.WithTestDB(t)
	_, _, info := setupTestUserAndSession(t)

	rr := mockAuthRequest(t, "", "DELETE", "/account/api/trusted-devices/", HandleRevokeTrustedDevice, info)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleRevokeTrustedDevice_Extra(t *testing.T) {
	testutils.WithTestDB(t)
	_, _, info := setupTestUserAndSession(t)

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /account/api/trusted-devices/{id}", HandleRevokeTrustedDevice)

	// Revoke nonexistent
	req := httptest.NewRequest("DELETE", "/account/api/trusted-devices/none", nil)
	req = middleware.WithAuthInfo(req, info)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
}
