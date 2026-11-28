package federation

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/reqid"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestCallbackEmailCollisionDiagnostics(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	for _, tc := range []struct {
		name                                                       string
		localVerified, upstreamVerified, omitVerified, deactivated bool
		newUser, linked, failCreate, success                       bool
	}{
		{name: "local unverified", upstreamVerified: true},
		{name: "upstream unverified", localVerified: true},
		{name: "both unverified"},
		{name: "missing upstream verification", localVerified: true, omitVerified: true},
		{name: "deactivated", localVerified: true, upstreamVerified: true, deactivated: true},
		{name: "both verified link", localVerified: true, upstreamVerified: true, success: true},
		{name: "existing identity takes precedence", linked: true, success: true},
		{name: "new account", newUser: true, upstreamVerified: true, success: true},
		{name: "unrelated creation failure", newUser: true, upstreamVerified: true, failCreate: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testutils.WithTestDB(t)
			testutils.WithConfigOverride(t, func() {
				config.Values.RequireMfa = false
				config.Values.AuthSsoEnabled = true
				config.Values.FederationCopyNameClaims = false
				config.Bootstrap.AuthIdpSessionSecureCookie = false
			})
			testutils.InsertTestClient(t, "rp", []string{"https://rp.example/callback"})
			if !tc.newUser {
				testutils.InsertTestUser(t, "local-user")
				_, err := db.GetDB().Exec(`UPDATE users SET email = 'private@example.test', is_email_verified = ? WHERE id = 'local-user'`, tc.localVerified)
				require.NoError(t, err)
				if tc.deactivated {
					_, err = db.GetDB().Exec(`UPDATE users SET deactivated_at = CURRENT_TIMESTAMP WHERE id = 'local-user'`)
					require.NoError(t, err)
				}
			}
			if tc.failCreate {
				_, err := db.GetDB().Exec(`CREATE TRIGGER reject_federated_user BEFORE INSERT ON users BEGIN SELECT RAISE(FAIL, 'injected creation failure'); END`)
				require.NoError(t, err)
			}

			var nonce atomic.Value
			nonce.Store("")
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				issuer := "http://" + r.Host
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/.well-known/openid-configuration":
					_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"}})
				case "/jwks":
					_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": "collision-key", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
				case "/token":
					claims := jwt.MapClaims{"iss": issuer, "aud": "upstream-client", "sub": "upstream-subject", "email": "private@example.test", "nonce": nonce.Load().(string), "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix()}
					if !tc.omitVerified {
						claims["email_verified"] = tc.upstreamVerified
					}
					token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
					token.Header["kid"] = "collision-key"
					signed, err := token.SignedString(key)
					if err != nil {
						t.Errorf("sign fixture token: %v", err)
						http.Error(w, "fixture error", 500)
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "upstream-access-secret", "token_type": "Bearer", "id_token": signed})
				default:
					http.NotFound(w, r)
				}
			}))
			defer upstream.Close()
			require.NoError(t, CreateFederationProvider(FederationProvider{ID: "upstream", Name: "Provider", Issuer: upstream.URL, ClientID: "upstream-client", ClientSecret: "upstream-client-secret", Enabled: true}))
			if tc.linked {
				require.NoError(t, CreateFederatedIdentity(FederatedIdentity{ProviderID: "upstream", ProviderUserID: "upstream-subject", UserID: "local-user"}))
			}
			state := FederationState{ProviderID: "upstream", ClientID: "rp", RedirectURI: "https://rp.example/callback", Scope: "openid", CodeChallenge: strings.Repeat("a", 43), CodeChallengeMethod: "S256"}
			signed, cookie := prepareTestLoginFlow(t, &state, nil)
			nonce.Store(state.FlowID)
			var logs bytes.Buffer
			old := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
			t.Cleanup(func() { slog.SetDefault(old) })
			r := httptest.NewRequest(http.MethodGet, "/callback?"+url.Values{"state": {signed}, "code": {"upstream-code-secret"}}.Encode(), nil)
			r.SetPathValue("id", "upstream")
			r.AddCookie(cookie)
			w := httptest.NewRecorder()
			handler := NewLoginHandler(upstream.Client())
			reqid.Middleware(http.HandlerFunc(handler.HandleCallback)).ServeHTTP(w, r)

			if tc.success {
				require.Equal(t, http.StatusFound, w.Code, w.Body.String())
				identity, err := FederatedIdentityByProviderAndSub("upstream", "upstream-subject")
				require.NoError(t, err)
				if !tc.newUser {
					require.Equal(t, "local-user", identity.UserID)
				}
				require.NotContains(t, logs.String(), "email collision")
			} else {
				require.Equal(t, http.StatusInternalServerError, w.Code)
				require.Equal(t, "Unable to complete sign-in. Try another sign-in method, or contact your administrator for help.\n", w.Body.String())
				require.Empty(t, w.Result().Cookies())
				require.Empty(t, w.Header().Get("Location"))
				requestID := w.Header().Get("X-Request-ID")
				require.NotEmpty(t, requestID)
				require.Contains(t, logs.String(), "request_id="+requestID)
				require.Contains(t, logs.String(), "provider_id=upstream")
				if tc.failCreate {
					require.Contains(t, logs.String(), "failed to create federated user")
					require.Contains(t, logs.String(), "injected creation failure")
					require.NotContains(t, logs.String(), "email collision")
				} else if tc.deactivated {
					require.Contains(t, logs.String(), "email collision prevented account linking: local account is deactivated")
					require.NotContains(t, logs.String(), "requires verified email")
				} else {
					require.Contains(t, logs.String(), "email collision prevented account linking: automatic linking requires verified email on both sides")
					require.Contains(t, logs.String(), fmt.Sprintf("local_email_verified=%t, upstream_email_verified=%t", tc.localVerified, tc.upstreamVerified))
					require.NotContains(t, logs.String(), "UNIQUE constraint failed")
				}
				for _, table := range []string{"federated_identities", "idp_sessions", "auth_codes"} {
					var count int
					require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM `+table).Scan(&count))
					require.Zero(t, count, table)
				}
			}
			var count int
			require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count))
			if tc.failCreate {
				require.Zero(t, count)
			} else {
				require.Equal(t, 1, count)
			}
			if !tc.newUser {
				var verified bool
				require.NoError(t, db.GetDB().QueryRow(`SELECT is_email_verified FROM users WHERE id = 'local-user'`).Scan(&verified))
				require.Equal(t, tc.localVerified, verified)
			}
			for _, secret := range []string{"private@example.test", "upstream-subject", "upstream-access-secret", "upstream-client-secret", "upstream-code-secret"} {
				require.NotContains(t, logs.String(), secret)
				require.NotContains(t, w.Body.String(), secret)
			}
		})
	}
}
