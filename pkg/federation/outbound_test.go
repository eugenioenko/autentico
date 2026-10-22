package federation

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

// TestCallbackBlocksDiscoveryDerivedPrivateEndpoints exercises real token/JWKS network attempts.
func TestCallbackBlocksDiscoveryDerivedPrivateEndpoints(t *testing.T) {
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	for _, phase := range []string{"token", "jwks"} {
		t.Run(phase, func(t *testing.T) {
			testutils.WithTestDB(t)
			testutils.InsertTestClient(t, "client", []string{"https://client.example/cb"})
			var reached atomic.Int32
			trap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { reached.Add(1); w.WriteHeader(200) }))
			defer trap.Close()
			const issuer = "https://issuer.example"
			require.NoError(t, CreateFederationProvider(FederationProvider{ID: "upstream", Name: "Upstream", Issuer: issuer, ClientID: "upstream-client", ClientSecret: "secret", Enabled: true}))
			tokenEndpoint, jwksEndpoint := issuer+"/token", issuer+"/jwks"
			if phase == "token" {
				tokenEndpoint = trap.URL + "/token"
			} else {
				jwksEndpoint = trap.URL + "/jwks"
			}
			idToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": issuer, "aud": "upstream-client", "sub": "subject", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix()})
			idToken.Header["kid"] = "test-signing-key"
			signed, err := idToken.SignedString(signingKey)
			require.NoError(t, err)
			client := safeHTTPClient()
			guarded := client.Transport.(*http.Transport)
			defer guarded.CloseIdleConnections()
			var exchanged atomic.Int32
			client.Transport = federationRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.Host != "issuer.example" {
					return guarded.RoundTrip(r)
				}
				var value any
				switch r.URL.Path {
				case "/.well-known/openid-configuration":
					value = map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": tokenEndpoint, "jwks_uri": jwksEndpoint, "id_token_signing_alg_values_supported": []string{"RS256"}}
				case "/token":
					exchanged.Add(1)
					value = map[string]any{"access_token": "upstream-access", "token_type": "Bearer", "id_token": signed}
				default:
					t.Errorf("unexpected public request: %s", r.URL)
					return federationResponse(r, 404, ""), nil
				}
				body, err := json.Marshal(value)
				if err != nil {
					return nil, err
				}
				resp := federationResponse(r, 200, string(body))
				resp.Header.Set("Content-Type", "application/json")
				return resp, nil
			})
			state, err := SignState(FederationState{ProviderID: "upstream", ClientID: "client", RedirectURI: "https://client.example/cb", Scope: "openid", CodeChallenge: "challenge", CodeChallengeMethod: "S256"})
			require.NoError(t, err)
			req := httptest.NewRequest(http.MethodGet, "/oauth2/federation/upstream/callback?"+url.Values{"state": {state}, "code": {"code"}}.Encode(), nil)
			req.SetPathValue("id", "upstream")
			rr := httptest.NewRecorder()
			NewLoginHandler(client).HandleCallback(rr, req)
			require.Equal(t, http.StatusUnauthorized, rr.Code)
			require.Zero(t, reached.Load(), "private endpoint must never receive an HTTP request")
			require.Empty(t, rr.Result().Cookies())
			if phase == "jwks" {
				require.EqualValues(t, 1, exchanged.Load(), "valid token response must reach signing-key verification")
			}
			for _, table := range []string{"users", "auth_codes", "idp_sessions", "tokens", "sessions"} {
				var count int
				require.NoError(t, db.GetDB().QueryRow("SELECT count(*) FROM "+table).Scan(&count))
				require.Zero(t, count, table)
			}
		})
	}
}
