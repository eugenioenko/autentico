package devicecode

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestDeviceAuthorizationAuthenticatesConfidentialClients(t *testing.T) {
	for _, tt := range []struct {
		name       string
		basic      bool
		secret     string
		malformed  bool
		inactive   bool
		noGrant    bool
		scope      string
		status     int
		oauthError string
	}{
		{name: "basic without form client ID", basic: true, secret: "device-secret", status: 200},
		{name: "form secret", secret: "device-secret", status: 200},
		{name: "missing secret", status: 400, oauthError: "invalid_client"},
		{name: "wrong form secret", secret: "wrong", status: 400, oauthError: "invalid_client"},
		{name: "wrong basic secret", basic: true, secret: "wrong", status: 401, oauthError: "invalid_client"},
		{name: "malformed basic cannot fall back to valid form credentials", malformed: true, secret: "device-secret", status: 401, oauthError: "invalid_client"},
		{name: "inactive basic client", basic: true, secret: "device-secret", inactive: true, status: 401, oauthError: "invalid_client"},
		{name: "inactive form client", secret: "device-secret", inactive: true, status: 400, oauthError: "invalid_client"},
		{name: "authenticated disallowed grant", basic: true, secret: "device-secret", noGrant: true, status: 400, oauthError: "unauthorized_client"},
		{name: "authenticated disallowed scope", basic: true, secret: "device-secret", scope: "openid forbidden", status: 400, oauthError: "invalid_scope"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			testutils.WithTestDB(t)
			authMethod := "client_secret_post"
			if tt.basic {
				authMethod = "client_secret_basic"
			}
			_, err := client.CreateClientWithID("confidential-device", client.ClientCreateRequest{
				ClientName: "Confidential device", ClientType: "confidential", ClientSecret: "device-secret",
				RedirectURIs: []string{"http://localhost/cb"}, GrantTypes: []string{DeviceCodeGrantType}, ResponseTypes: []string{"code"},
				Scopes: "openid profile", TokenEndpointAuthMethod: authMethod,
			})
			require.NoError(t, err)
			if tt.inactive {
				_, err = db.GetDB().Exec(`UPDATE clients SET is_active=FALSE WHERE client_id='confidential-device'`)
				require.NoError(t, err)
			}
			if tt.noGrant {
				_, err = db.GetDB().Exec(`UPDATE clients SET grant_types='["authorization_code"]' WHERE client_id='confidential-device'`)
				require.NoError(t, err)
			}
			scope := tt.scope
			if scope == "" {
				scope = "openid"
			}
			form := url.Values{"scope": {scope}}
			if !tt.basic {
				form.Set("client_id", "confidential-device")
				if tt.secret != "" {
					form.Set("client_secret", tt.secret)
				}
			}
			r := httptest.NewRequest(http.MethodPost, "/oauth2/device_authorization", strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tt.basic {
				r.SetBasicAuth("confidential-device", tt.secret)
			}
			if tt.malformed {
				r.Header.Set("Authorization", "Basic definitely-not-base64")
			}
			rr := httptest.NewRecorder()
			HandleDeviceAuthorization(rr, r)
			require.Equal(t, tt.status, rr.Code, rr.Body.String())
			var count int
			require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM device_codes`).Scan(&count))
			if tt.status == http.StatusOK {
				require.Equal(t, 1, count)
				var response DeviceAuthorizationResponse
				require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &response))
				require.NotEmpty(t, response.DeviceCode)
				var storedClient string
				require.NoError(t, db.GetDB().QueryRow(`SELECT client_id FROM device_codes WHERE code=?`, response.DeviceCode).Scan(&storedClient))
				require.Equal(t, "confidential-device", storedClient)
			} else {
				require.Zero(t, count, "rejected authentication or policy must not create a device code")
				var response struct {
					Error string `json:"error"`
				}
				require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &response))
				require.Equal(t, tt.oauthError, response.Error)
				if tt.status == http.StatusUnauthorized {
					require.Equal(t, `Basic realm="device_authorization"`, rr.Header().Get("WWW-Authenticate"))
				}
			}
		})
	}
}

func TestDeviceAuthorizationRejectsInactivePublicClients(t *testing.T) {
	testutils.WithTestDB(t)
	createTestClient(t)
	_, err := db.GetDB().Exec(`UPDATE clients SET is_active=FALSE WHERE client_id='device-test-client'`)
	require.NoError(t, err)
	r := httptest.NewRequest(http.MethodPost, "/oauth2/device_authorization", strings.NewReader("client_id=device-test-client&scope=openid"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleDeviceAuthorization(rr, r)
	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Contains(t, rr.Body.String(), "invalid_client")
	var count int
	require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM device_codes`).Scan(&count))
	require.Zero(t, count)
}
