package federation

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestCallbackChecksUpstreamNonceBeforeAccountOrSessionChanges(t *testing.T) {
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	for _, nonceMode := range []string{"valid", "missing", "wrong"} {
		t.Run(nonceMode, func(t *testing.T) {
			testutils.WithTestDB(t)
			testutils.WithConfigOverride(t, func() {
				config.Values.AuthAllowSelfSignup = true
				config.Values.RequireMfa = false
				config.Values.AuthSsoEnabled = true
				config.Bootstrap.AuthIdpSessionSecureCookie = false
			})
			testutils.InsertTestClient(t, "rp", []string{"https://rp.example/cb?registered=kept"})
			var requests atomic.Int32
			var expectedNonce atomic.Value
			expectedNonce.Store("")
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.Header().Set("Content-Type", "application/json")
				issuer := "http://" + r.Host
				switch r.URL.Path {
				case "/.well-known/openid-configuration":
					_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"}})
				case "/token":
					claims := jwt.MapClaims{"iss": issuer, "aud": "upstream-client", "sub": "upstream-owner", "email": "flow-owner@example.test", "email_verified": true, "exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix()}
					switch nonceMode {
					case "valid":
						claims["nonce"] = expectedNonce.Load().(string)
					case "wrong":
						claims["nonce"] = "different-flow"
					}
					idToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
					idToken.Header["kid"] = "flow-key"
					signed, err := idToken.SignedString(signingKey)
					if err != nil {
						t.Errorf("sign fixture ID token: %v", err)
						http.Error(w, "fixture error", 500)
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "upstream-access", "token_type": "Bearer", "id_token": signed})
				case "/jwks":
					_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": "flow-key", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(signingKey.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(signingKey.E)).Bytes())}}})
				default:
					http.NotFound(w, r)
				}
			}))
			defer upstream.Close()
			require.NoError(t, CreateFederationProvider(FederationProvider{ID: "upstream", Name: "Upstream", Issuer: upstream.URL, ClientID: "upstream-client", ClientSecret: "upstream-secret", Enabled: true}))
			handler := NewLoginHandler(upstream.Client())
			params := url.Values{"client_id": {"rp"}, "redirect_uri": {"https://rp.example/cb?registered=kept"}, "scope": {"openid profile email"}, "state": {"opaque & state"}, "nonce": {"original-rp-nonce"}, "code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}, "code_challenge_method": {"S256"}}
			begin := httptest.NewRequest(http.MethodGet, "/oauth2/federation/upstream?"+params.Encode(), nil)
			begin.SetPathValue("id", "upstream")
			rr := httptest.NewRecorder()
			handler.HandleBegin(rr, begin)
			require.Equal(t, http.StatusFound, rr.Code, rr.Body.String())
			authorizeURL, err := url.Parse(rr.Header().Get("Location"))
			require.NoError(t, err)
			signedState := authorizeURL.Query().Get("state")
			state, err := VerifyState(signedState)
			require.NoError(t, err)
			require.Equal(t, "original-rp-nonce", state.Nonce)
			require.NotEqual(t, state.Nonce, state.FlowID)
			require.Equal(t, state.FlowID, authorizeURL.Query().Get("nonce"))
			expectedNonce.Store(state.FlowID)
			cookies := rr.Result().Cookies()
			require.Len(t, cookies, 1)
			cookie := cookies[0]
			callback := func(binding *http.Cookie) *httptest.ResponseRecorder {
				r := httptest.NewRequest(http.MethodGet, "/oauth2/federation/upstream/callback?"+url.Values{"state": {signedState}, "code": {"upstream-code"}}.Encode(), nil)
				r.SetPathValue("id", "upstream")
				if binding != nil {
					r.AddCookie(binding)
				}
				rr := httptest.NewRecorder()
				handler.HandleCallback(rr, r)
				return rr
			}
			before := requests.Load()
			if nonceMode == "valid" {
				// Both absent and independently valid browser cookies must fail before
				// even rediscovering the provider, without consuming the owner's record.
				other, err := randomFlowValue()
				require.NoError(t, err)
				for _, binding := range []*http.Cookie{nil, {Name: cookie.Name, Value: other}} {
					rejected := callback(binding)
					require.Equal(t, http.StatusBadRequest, rejected.Code, rejected.Body.String())
					require.Empty(t, rejected.Result().Cookies())
					require.Equal(t, before, requests.Load())
					require.Equal(t, 1, flowRowCount(t))
				}
				_, err = db.GetDB().Exec(`CREATE TRIGGER reject_callback_flow BEFORE DELETE ON federation_login_flows BEGIN SELECT RAISE(FAIL,'injected callback failure'); END`)
				require.NoError(t, err)
				rejected := callback(cookie)
				require.Equal(t, http.StatusInternalServerError, rejected.Code)
				require.Empty(t, rejected.Result().Cookies())
				require.Equal(t, before, requests.Load())
				require.Equal(t, 1, flowRowCount(t))
				_, err = db.GetDB().Exec(`DROP TRIGGER reject_callback_flow`)
				require.NoError(t, err)
			}
			completed := callback(cookie)
			expectedStatus := http.StatusUnauthorized
			if nonceMode == "valid" {
				expectedStatus = http.StatusFound
			}
			require.Equal(t, expectedStatus, completed.Code, completed.Body.String())
			require.Greater(t, requests.Load(), before)
			require.Zero(t, flowRowCount(t))
			for _, table := range []string{"users", "auth_codes", "idp_sessions", "federated_identities"} {
				var count int
				require.NoError(t, db.GetDB().QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s", table)).Scan(&count))
				if nonceMode == "valid" {
					require.Equal(t, 1, count, table)
				} else {
					require.Zero(t, count, table)
				}
			}
			if nonceMode == "valid" {
				target, err := url.Parse(completed.Header().Get("Location"))
				require.NoError(t, err)
				require.Equal(t, "https://rp.example/cb", target.Scheme+"://"+target.Host+target.Path)
				require.Equal(t, "kept", target.Query().Get("registered"))
				require.Equal(t, "opaque & state", target.Query().Get("state"))
				require.NotEmpty(t, target.Query().Get("code"))
				var nonce string
				require.NoError(t, db.GetDB().QueryRow(`SELECT nonce FROM auth_codes WHERE code=?`, target.Query().Get("code")).Scan(&nonce))
				require.Equal(t, "original-rp-nonce", nonce)
			} else {
				require.Empty(t, completed.Result().Cookies())
			}
			before = requests.Load()
			replay := callback(cookie)
			require.Equal(t, http.StatusBadRequest, replay.Code)
			require.Empty(t, replay.Result().Cookies())
			require.Equal(t, before, requests.Load(), "replay must not contact the upstream again")
		})
	}
}
