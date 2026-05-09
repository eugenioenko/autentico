package token

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
	"github.com/eugenioenko/autentico/pkg/devicecode"
	"github.com/eugenioenko/autentico/pkg/user"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupDeviceCodeTest(t *testing.T) (string, string) {
	t.Helper()
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.DeviceCodeExpiration = 10 * time.Minute
		config.Values.DeviceCodePollingInterval = 5
	})

	_, err := client.CreateClientWithID("device-client", client.ClientCreateRequest{
		ClientName:              "Device Client",
		ClientType:              "public",
		RedirectURIs:            []string{"http://localhost:3000/callback"},
		GrantTypes:              []string{"authorization_code", "urn:ietf:params:oauth:grant-type:device_code"},
		ResponseTypes:           []string{"code"},
		Scopes:                  "openid profile email",
		TokenEndpointAuthMethod: "none",
	})
	require.NoError(t, err)

	usr, err := user.CreateUser("deviceuser", "password123", "device@test.com")
	require.NoError(t, err)

	dc := devicecode.DeviceCode{
		Code:            "test-device-code-poll",
		UserCode:        "BCDFGHJK",
		ClientID:        "device-client",
		Scope:           "openid profile",
		ExpiresAt:       time.Now().Add(10 * time.Minute),
		IntervalSeconds: 5,
		Status:          "pending",
	}
	require.NoError(t, devicecode.CreateDeviceCode(dc))

	return usr.ID, dc.Code
}

func TestDeviceCodeGrant_AuthorizationPending(t *testing.T) {
	_, code := setupDeviceCodeTest(t)

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	form.Set("device_code", code)
	form.Set("client_id", "device-client")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleToken(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var resp map[string]string
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, "authorization_pending", resp["error"])
}

func TestDeviceCodeGrant_AccessDenied(t *testing.T) {
	_, code := setupDeviceCodeTest(t)
	require.NoError(t, devicecode.DenyDeviceCode("BCDFGHJK"))

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	form.Set("device_code", code)
	form.Set("client_id", "device-client")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleToken(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var resp map[string]string
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, "access_denied", resp["error"])
}

func TestDeviceCodeGrant_ExpiredToken(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.DeviceCodeExpiration = 10 * time.Minute
		config.Values.DeviceCodePollingInterval = 5
	})

	_, err := client.CreateClientWithID("device-client", client.ClientCreateRequest{
		ClientName:              "Device Client",
		ClientType:              "public",
		RedirectURIs:            []string{"http://localhost:3000/callback"},
		GrantTypes:              []string{"authorization_code", "urn:ietf:params:oauth:grant-type:device_code"},
		ResponseTypes:           []string{"code"},
		Scopes:                  "openid profile email",
		TokenEndpointAuthMethod: "none",
	})
	require.NoError(t, err)

	dc := devicecode.DeviceCode{
		Code:            "expired-device-code",
		UserCode:        "LMNPQRST",
		ClientID:        "device-client",
		Scope:           "openid",
		ExpiresAt:       time.Now().Add(-1 * time.Minute), // already expired
		IntervalSeconds: 5,
		Status:          "pending",
	}
	require.NoError(t, devicecode.CreateDeviceCode(dc))

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	form.Set("device_code", "expired-device-code")
	form.Set("client_id", "device-client")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleToken(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var resp map[string]string
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, "expired_token", resp["error"])
}

func TestDeviceCodeGrant_Success(t *testing.T) {
	userID, code := setupDeviceCodeTest(t)
	require.NoError(t, devicecode.AuthorizeDeviceCode("BCDFGHJK", userID))

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	form.Set("device_code", code)
	form.Set("client_id", "device-client")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleToken(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp TokenResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)
	assert.Equal(t, "Bearer", resp.TokenType)
	assert.Equal(t, "openid profile", resp.Scope)
}

func TestDeviceCodeGrant_MissingDeviceCode(t *testing.T) {
	testutils.WithTestDB(t)

	_, err := client.CreateClientWithID("device-client", client.ClientCreateRequest{
		ClientName:              "Device Client",
		ClientType:              "public",
		RedirectURIs:            []string{"http://localhost:3000/callback"},
		GrantTypes:              []string{"authorization_code", "urn:ietf:params:oauth:grant-type:device_code"},
		ResponseTypes:           []string{"code"},
		Scopes:                  "openid profile email",
		TokenEndpointAuthMethod: "none",
	})
	require.NoError(t, err)

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	form.Set("client_id", "device-client")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleToken(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "device_code is required")
}
