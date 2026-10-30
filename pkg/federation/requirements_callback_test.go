package federation

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
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
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestClaimRequirementsRejectBeforeLocalSideEffects(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	for _, tc := range []struct {
		name              string
		claims            map[string]any
		rules             ClaimRequirements
		linked, pass, mfa bool
		change            string
	}{
		{name: "matching new user", claims: map[string]any{"org": "allowed"}, rules: ClaimRequirements{{"org", "equals", "allowed"}}, pass: true},
		{name: "matching linked user", claims: map[string]any{"org": "allowed"}, rules: ClaimRequirements{{"org", "equals", "allowed"}}, linked: true, pass: true},
		{name: "matching still requires local MFA", claims: map[string]any{"org": "allowed"}, rules: ClaimRequirements{{"org", "equals", "allowed"}}, pass: true, mfa: true},
		{name: "empty policy preserves login", pass: true},
		{name: "new user denied", claims: map[string]any{"org": "denied-secret"}, rules: ClaimRequirements{{"org", "equals", "allowed-secret"}}},
		{name: "linked user denied", claims: map[string]any{"org": "denied-secret"}, rules: ClaimRequirements{{"org", "equals", "allowed-secret"}}, linked: true},
		{name: "missing negative claim", rules: ClaimRequirements{{"status", "not_equals", "suspended"}}},
		{name: "null negative claim", claims: map[string]any{"status": nil}, rules: ClaimRequirements{{"status", "not_equals", "suspended"}}},
		{name: "wrong type negative claim", claims: map[string]any{"status": true}, rules: ClaimRequirements{{"status", "not_regex", "suspended"}}},
		{name: "one failing row", claims: map[string]any{"org": "allowed", "email_verified": true}, rules: ClaimRequirements{{"org", "equals", "allowed"}, {"email_verified", "equals", false}}},
		{name: "policy changed during exchange", claims: map[string]any{"org": "allowed"}, change: "policy"},
		{name: "disabled during exchange", change: "disabled"},
		{name: "identity changed during exchange", change: "identity"},
		{name: "invalid stored policy", change: "invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testutils.WithTestDB(t)
			testutils.WithConfigOverride(t, func() {
				config.Values.AuthAllowSelfSignup = true
				config.Values.RequireMfa = tc.mfa
				config.Values.MfaMethod = "totp"
				config.Values.TrustDeviceEnabled = false
				config.Bootstrap.AuthIdpSessionSecureCookie = false
			})
			testutils.InsertTestClient(t, "rp", []string{"https://rp.example/callback"})
			if tc.linked {
				testutils.InsertTestUser(t, "linked-user")
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
					_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": "rules-key", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
				case "/token":
					var updateErr error
					switch tc.change {
					case "policy":
						_, updateErr = db.GetDB().Exec(`UPDATE federation_providers SET claim_requirements='[{"claim":"org","match":"equals","value":"now-denied"}]' WHERE id='upstream'`)
					case "disabled":
						_, updateErr = db.GetDB().Exec(`UPDATE federation_providers SET enabled=FALSE WHERE id='upstream'`)
					case "identity":
						_, updateErr = db.GetDB().Exec(`UPDATE federation_providers SET client_id='changed' WHERE id='upstream'`)
					case "invalid":
						_, updateErr = db.GetDB().Exec(`UPDATE federation_providers SET claim_requirements='[{"claim":"org","match":"unsupported","value":"x"}]' WHERE id='upstream'`)
					}
					if updateErr != nil {
						http.Error(w, "fixture update failed", 500)
						return
					}
					claims := jwt.MapClaims{"iss": issuer, "aud": "upstream-client", "sub": "subject", "email": "private@example.test", "email_verified": true, "nonce": nonce.Load().(string), "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix()}
					for k, v := range tc.claims {
						claims[k] = v
					}
					token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
					token.Header["kid"] = "rules-key"
					signed, e := token.SignedString(key)
					if e != nil {
						http.Error(w, "sign failed", 500)
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "upstream-secret", "token_type": "Bearer", "id_token": signed})
				default:
					http.NotFound(w, r)
				}
			}))
			defer upstream.Close()
			require.NoError(t, CreateFederationProvider(FederationProvider{ID: "upstream", Name: "Provider", Issuer: upstream.URL, ClientID: "upstream-client", ClientSecret: "upstream-secret", Enabled: true, ClaimRequirements: tc.rules}))
			// An already-linked user must be gated just like a new account.
			if tc.linked {
				require.NoError(t, CreateFederatedIdentity(FederatedIdentity{ProviderID: "upstream", ProviderUserID: "subject", UserID: "linked-user"}))
			}
			state := FederationState{ProviderID: "upstream", ClientID: "rp", RedirectURI: "https://rp.example/callback", Scope: "openid", State: "rp-state", CodeChallenge: strings.Repeat("a", 43), CodeChallengeMethod: "S256"}
			signed, cookie := prepareTestLoginFlow(t, &state, nil)
			nonce.Store(state.FlowID)
			before := map[string]int{}
			for _, table := range []string{"users", "federated_identities", "idp_sessions", "auth_codes"} {
				var n int
				require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM `+table).Scan(&n))
				before[table] = n
			}
			var logs bytes.Buffer
			old := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
			defer slog.SetDefault(old)
			r := httptest.NewRequest("GET", "/callback?"+url.Values{"state": {signed}, "code": {"upstream-code"}}.Encode(), nil)
			r.SetPathValue("id", "upstream")
			r.AddCookie(cookie)
			w := httptest.NewRecorder()
			NewLoginHandler(upstream.Client()).HandleCallback(w, r)
			if !tc.pass {
				require.Equal(t, 403, w.Code, w.Body.String())
				require.Empty(t, w.Result().Cookies())
				require.Empty(t, w.Header().Get("Location"))
				for table, n := range before {
					var after int
					require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM `+table).Scan(&after))
					require.Equal(t, n, after, table)
				}
				for _, secret := range []string{"private@example.test", "denied-secret", "allowed-secret", "upstream-secret"} {
					require.NotContains(t, logs.String(), secret)
					require.NotContains(t, w.Body.String(), secret)
				}
			} else {
				require.Equal(t, 302, w.Code, w.Body.String())
				target, err := url.Parse(w.Header().Get("Location"))
				require.NoError(t, err)
				if tc.mfa {
					require.Equal(t, "/oauth2/mfa", target.Path)
					var n int
					require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM auth_codes`).Scan(&n))
					require.Zero(t, n)
				} else {
					require.NotEmpty(t, target.Query().Get("code"))
				}
			}
		})
	}
}
