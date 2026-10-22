package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

// RFC 7591 §2 and §3.2.1: effective client type, issued secrets and returned
// authentication metadata must agree, including when extensions are omitted.
func TestClientRegistrationAuthenticationMetadata(t *testing.T) {
	for _, clientType := range []string{"", "public", "confidential", "unsupported"} {
		for _, method := range []string{"", "none", "client_secret_basic", "client_secret_post", "unsupported"} {
			t.Run(clientType+"/"+method, func(t *testing.T) {
				testutils.WithTestDB(t)
				request := ClientCreateRequest{ClientName: "Metadata", RedirectURIs: []string{"http://localhost/callback"}, ClientType: clientType, TokenEndpointAuthMethod: method}
				contradictory := clientType == "unsupported" || method == "unsupported" || (clientType == "public" && method != "" && method != "none") || (clientType == "confidential" && method == "none")
				validationErr := ValidateClientCreateRequest(request)
				created, err := CreateClient(request)
				if contradictory {
					require.Error(t, validationErr)
					require.Error(t, err)
					var count int
					require.NoError(t, db.GetDB().QueryRow("SELECT count(*) FROM clients").Scan(&count))
					require.Zero(t, count)
					return
				}
				require.NoError(t, validationErr)
				require.NoError(t, err)
				expectedType := clientType
				if expectedType == "" {
					if method == "none" {
						expectedType = "public"
					} else {
						expectedType = "confidential"
					}
				}
				expectedMethod := method
				if expectedMethod == "" {
					if expectedType == "public" {
						expectedMethod = "none"
					} else {
						expectedMethod = "client_secret_basic"
					}
				}
				require.Equal(t, expectedType, created.ClientType)
				require.Equal(t, expectedMethod, created.TokenEndpointAuthMethod)
				stored, err := ClientByClientID(created.ClientID)
				require.NoError(t, err)
				require.Equal(t, expectedType, stored.ClientType)
				require.Equal(t, expectedMethod, stored.TokenEndpointAuthMethod)
				require.Equal(t, expectedMethod, stored.ToInfoResponse().TokenEndpointAuthMethod)
				if expectedType == "public" {
					require.Empty(t, created.ClientSecret)
					require.Empty(t, stored.ClientSecret)
					_, err = AuthenticateClient(created.ClientID, "")
					require.NoError(t, err)
				} else {
					require.NotEmpty(t, created.ClientSecret)
					require.NotEqual(t, created.ClientSecret, stored.ClientSecret)
					_, err = AuthenticateClient(created.ClientID, "")
					require.Error(t, err)
					_, err = AuthenticateClient(created.ClientID, created.ClientSecret)
					require.NoError(t, err)
				}
			})
		}
	}
}

func TestClientUpdateRejectsContradictoryAuthenticationMetadata(t *testing.T) {
	for _, clientType := range []string{"public", "confidential"} {
		for _, method := range []string{"none", "client_secret_basic", "client_secret_post"} {
			t.Run(clientType+"/"+method, func(t *testing.T) {
				testutils.WithTestDB(t)
				created, err := CreateClient(ClientCreateRequest{ClientName: "Original", RedirectURIs: []string{"http://localhost/callback"}, ClientType: clientType})
				require.NoError(t, err)
				before, err := ClientByClientID(created.ClientID)
				require.NoError(t, err)
				payload, _ := json.Marshal(ClientUpdateRequest{ClientName: "Changed", TokenEndpointAuthMethod: method})
				req := httptest.NewRequest(http.MethodPut, "/oauth2/register/"+created.ClientID, strings.NewReader(string(payload)))
				req.SetPathValue("client_id", created.ClientID)
				rr := httptest.NewRecorder()
				HandleUpdateClient(rr, req)
				contradictory := (clientType == "public") != (method == "none")
				stored, err := ClientByClientID(created.ClientID)
				require.NoError(t, err)
				require.Equal(t, before.ClientSecret, stored.ClientSecret)
				require.Equal(t, before.ClientType, stored.ClientType)
				if contradictory {
					require.Equal(t, http.StatusBadRequest, rr.Code)
					require.Contains(t, rr.Body.String(), "invalid_client_metadata")
					require.Equal(t, before.ClientName, stored.ClientName)
					require.Equal(t, before.TokenEndpointAuthMethod, stored.TokenEndpointAuthMethod)
					// Direct internal callers must enforce the same invariant.
					require.Error(t, UpdateClient(created.ClientID, ClientUpdateRequest{TokenEndpointAuthMethod: method}))
				} else {
					require.Equal(t, http.StatusOK, rr.Code)
					require.Equal(t, "Changed", stored.ClientName)
					require.Equal(t, method, stored.TokenEndpointAuthMethod)
				}
			})
		}
	}
}

func TestLegacyClientAuthenticationMetadataPreservesCredentials(t *testing.T) {
	for _, tc := range []struct{ clientType, legacyMethod, effectiveMethod string }{
		{"confidential", "none", "client_secret_basic"},
		{"confidential", "", "client_secret_basic"},
		{"public", "client_secret_basic", "none"},
		{"public", "client_secret_post", "none"},
	} {
		t.Run(tc.clientType+"/"+tc.legacyMethod, func(t *testing.T) {
			testutils.WithTestDB(t)
			created, err := CreateClient(ClientCreateRequest{ClientName: "Legacy", RedirectURIs: []string{"http://localhost/callback"}, ClientType: tc.clientType})
			require.NoError(t, err)
			before, err := ClientByClientID(created.ClientID)
			require.NoError(t, err)
			_, err = db.GetDB().Exec("UPDATE clients SET token_endpoint_auth_method=? WHERE client_id=?", tc.legacyMethod, created.ClientID)
			require.NoError(t, err)
			stored, err := ClientByClientID(created.ClientID)
			require.NoError(t, err)
			require.Equal(t, tc.effectiveMethod, stored.ToInfoResponse().TokenEndpointAuthMethod)
			require.Equal(t, tc.clientType, stored.ClientType)
			require.Equal(t, before.ClientSecret, stored.ClientSecret)
			_, err = AuthenticateClient(created.ClientID, "")
			if tc.clientType == "confidential" {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			_, err = AuthenticateClient(created.ClientID, created.ClientSecret)
			require.NoError(t, err)
			// Updating unrelated metadata repairs the stored method without changing
			// client type or credentials, even for a disabled historical registration.
			_, err = db.GetDB().Exec("UPDATE clients SET is_active=FALSE WHERE client_id=?", created.ClientID)
			require.NoError(t, err)
			require.NoError(t, UpdateClient(created.ClientID, ClientUpdateRequest{ClientName: "Repaired"}))
			repaired, err := ClientByClientIDIncludingDisabled(created.ClientID)
			require.NoError(t, err)
			require.Equal(t, tc.effectiveMethod, repaired.TokenEndpointAuthMethod)
			require.Equal(t, tc.clientType, repaired.ClientType)
			require.Equal(t, before.ClientSecret, repaired.ClientSecret)
			require.False(t, repaired.IsActive)
		})
	}
}
