package devicecode

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/config"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestClient(t *testing.T) {
	t.Helper()
	_, err := client.CreateClientWithID("device-test-client", client.ClientCreateRequest{
		ClientName:              "Device Test Client",
		ClientType:              "public",
		RedirectURIs:            []string{"http://localhost:3000/callback"},
		GrantTypes:              []string{"authorization_code", "urn:ietf:params:oauth:grant-type:device_code"},
		ResponseTypes:           []string{"code"},
		Scopes:                  "openid profile email",
		TokenEndpointAuthMethod: "none",
	})
	require.NoError(t, err)
}

func TestHandleDeviceAuthorization_Success(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.DeviceCodeExpiration = 10 * time.Minute
		config.Values.DeviceCodePollingInterval = 5
	})
	createTestClient(t)

	form := url.Values{}
	form.Set("client_id", "device-test-client")
	form.Set("scope", "openid profile")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/device_authorization", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleDeviceAuthorization(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp DeviceAuthorizationResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.NotEmpty(t, resp.DeviceCode)
	assert.NotEmpty(t, resp.UserCode)
	assert.Contains(t, resp.UserCode, "-")
	assert.Equal(t, 600, resp.ExpiresIn)
	assert.Equal(t, 5, resp.Interval)
	assert.Contains(t, resp.VerificationURI, "/device")
	assert.Contains(t, resp.VerificationURIComplete, "/account/device/")
	assert.Contains(t, resp.VerificationURIComplete, resp.UserCode)
}

func TestHandleDeviceAuthorization_MissingClientID(t *testing.T) {
	testutils.WithTestDB(t)

	form := url.Values{}
	form.Set("scope", "openid")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/device_authorization", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleDeviceAuthorization(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "client_id is required")
}

func TestHandleDeviceAuthorization_UnknownClient(t *testing.T) {
	testutils.WithTestDB(t)

	form := url.Values{}
	form.Set("client_id", "nonexistent-client")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/device_authorization", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleDeviceAuthorization(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_client")
}

func TestHandleDeviceAuthorization_GrantTypeNotAllowed(t *testing.T) {
	testutils.WithTestDB(t)

	// Create client without device_code grant
	_, err := client.CreateClientWithID("no-device-client", client.ClientCreateRequest{
		ClientName:              "No Device Client",
		ClientType:              "public",
		RedirectURIs:            []string{"http://localhost:3000/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		Scopes:                  "openid",
		TokenEndpointAuthMethod: "none",
	})
	require.NoError(t, err)

	form := url.Values{}
	form.Set("client_id", "no-device-client")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/device_authorization", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleDeviceAuthorization(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "unauthorized_client")
}

func TestHandleDeviceAuthorization_WrongMethod(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/device_authorization", nil)
	rr := httptest.NewRecorder()

	HandleDeviceAuthorization(rr, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}

func TestHandleDeviceAuthorization_InvalidScope(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.DeviceCodeExpiration = 10 * time.Minute
		config.Values.DeviceCodePollingInterval = 5
	})
	createTestClient(t)

	form := url.Values{}
	form.Set("client_id", "device-test-client")
	form.Set("scope", "openid admin_super_scope")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/device_authorization", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleDeviceAuthorization(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_scope")
}
