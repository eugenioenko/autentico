package security

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/federation"
	"github.com/eugenioenko/autentico/pkg/key"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

// A real discovery document, signed ID token and JWKS exercise the whole
// federation callback rather than stopping at a mocked token-verification error.
func federationIssuer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	requests := new(atomic.Int32)
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		base := "http://" + r.Host
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer": base, "authorization_endpoint": base + "/authorize",
				"token_endpoint": base + "/token", "jwks_uri": base + "/jwks",
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/token":
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"iss": base, "aud": "upstream-client", "sub": "victim-subject",
				"iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(),
				"email": "federation-victim@example.com", "email_verified": true,
			})
			token.Header["kid"] = "test-upstream"
			signed, err := token.SignedString(key.GetPrivateKey())
			if err != nil {
				t.Errorf("sign upstream token: %v", err)
				http.Error(w, "signing failed", 500)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "upstream-access", "token_type": "Bearer", "id_token": signed})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{key.GetRSAPublicKeyJWK("test-upstream")}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(issuer.Close)
	require.NoError(t, federation.CreateFederationProvider(federation.FederationProvider{
		ID: "test-idp", Name: "Test IdP", Issuer: issuer.URL,
		ClientID: "upstream-client", ClientSecret: "upstream-secret", Enabled: true,
	}))
	return issuer, requests
}

func federationParams() url.Values {
	return url.Values{
		"client_id": {"test-client"}, "redirect_uri": {"http://localhost:3000/callback"},
		"scope": {"openid email"}, "state": {"original-state"},
		"code_challenge": {testCodeChallenge}, "code_challenge_method": {"S256"},
	}
}

func signedFederationState(t *testing.T, p url.Values) string {
	t.Helper()
	signed, err := federation.SignState(federation.FederationState{
		ProviderID: "test-idp", ClientID: p.Get("client_id"), RedirectURI: p.Get("redirect_uri"),
		Scope: p.Get("scope"), State: p.Get("state"), Nonce: p.Get("nonce"),
		CodeChallenge: p.Get("code_challenge"), CodeChallengeMethod: p.Get("code_challenge_method"),
	})
	require.NoError(t, err)
	return signed
}

func requireNoFederationArtifacts(t *testing.T) {
	t.Helper()
	for _, table := range []string{"auth_codes", "idp_sessions", "tokens", "sessions", "users"} {
		var count int
		require.NoError(t, db.GetDB().QueryRow("SELECT count(*) FROM "+table).Scan(&count))
		require.Zero(t, count, table)
	}
}

// RFC 6749 §4.1.2.1 / §10.6: reject unregistered destinations locally, before
// signing state or contacting an identity provider, including on direct entry.
func TestFederation_RejectsInvalidAuthorization(t *testing.T) {
	for _, tc := range []struct{ name, field, value, sql string }{
		{name: "missing client", field: "client_id"},
		{name: "unknown client", field: "client_id", value: "unknown"},
		{name: "inactive client", sql: "UPDATE clients SET is_active=FALSE WHERE client_id='test-client'"},
		{name: "attacker redirect", field: "redirect_uri", value: "https://attacker.example/steal"},
		{name: "missing redirect", field: "redirect_uri"},
		{name: "disallowed scope", field: "scope", value: "openid custom_claims"},
		{name: "missing PKCE", field: "code_challenge"},
		{name: "plain PKCE", field: "code_challenge_method", value: "plain"},
		{name: "unknown PKCE", field: "code_challenge_method", value: "S512"},
		{name: "disallowed grant", sql: `UPDATE clients SET grant_types='["password"]' WHERE client_id='test-client'`},
		{name: "disallowed response", sql: `UPDATE clients SET response_types='[]' WHERE client_id='test-client'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := startTestServer(t)
			_, requests := federationIssuer(t)
			p := federationParams()
			if tc.field != "" {
				p.Set(tc.field, tc.value)
			}
			// Represents state signed before a registration change or by an older binary.
			signed := signedFederationState(t, p)
			if tc.sql != "" {
				_, err := db.GetDB().Exec(tc.sql)
				require.NoError(t, err)
			}
			for _, path := range []string{
				"/oauth2/federation/test-idp/begin?" + p.Encode(),
				"/oauth2/federation/test-idp/callback?" + url.Values{"state": {signed}, "code": {"upstream-code"}}.Encode(),
			} {
				resp, err := ts.Client.Get(ts.BaseURL + path)
				require.NoError(t, err)
				_ = resp.Body.Close()
				require.Equal(t, http.StatusBadRequest, resp.StatusCode)
				require.Empty(t, resp.Header.Get("Location"))
				require.Empty(t, resp.Cookies())
			}
			require.Zero(t, requests.Load(), "invalid authorization must not contact the provider")
			requireNoFederationArtifacts(t)
		})
	}
}

// RFC 6749 §4.1.2 / §4.1.3: legitimate federation still produces a client-bound,
// PKCE-protected code, preserving existing callback query parameters and state.
func TestFederation_ValidFlowAndRegistrationChange(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid", true: "redirect removed during login"}[changed], func(t *testing.T) {
			ts := startTestServer(t)
			_, requests := federationIssuer(t)
			redirect := "http://localhost:3000/callback?existing=kept"
			_, err := db.GetDB().Exec(`UPDATE clients SET redirect_uris=? WHERE client_id='test-client'`, `["`+redirect+`"]`)
			require.NoError(t, err)
			p := federationParams()
			p.Set("redirect_uri", redirect)
			p.Set("state", "original &code=attacker#fragment?unicode=é")
			resp, err := ts.Client.Get(ts.BaseURL + "/oauth2/federation/test-idp/begin?" + p.Encode())
			require.NoError(t, err)
			_ = resp.Body.Close()
			require.Equal(t, http.StatusFound, resp.StatusCode)
			upstream, err := url.Parse(resp.Header.Get("Location"))
			require.NoError(t, err)
			signed := upstream.Query().Get("state")
			require.NotEmpty(t, signed)
			if changed {
				_, err := db.GetDB().Exec(`UPDATE clients SET redirect_uris='[]' WHERE client_id='test-client'`)
				require.NoError(t, err)
			}
			before := requests.Load()
			resp, err = ts.Client.Get(ts.BaseURL + "/oauth2/federation/test-idp/callback?" + url.Values{"state": {signed}, "code": {"upstream-code"}}.Encode())
			require.NoError(t, err)
			_ = resp.Body.Close()
			if changed {
				require.Equal(t, http.StatusBadRequest, resp.StatusCode)
				require.Empty(t, resp.Header.Get("Location"))
				require.Equal(t, before, requests.Load())
				requireNoFederationArtifacts(t)
				return
			}
			require.Equal(t, http.StatusFound, resp.StatusCode)
			callback, err := url.Parse(resp.Header.Get("Location"))
			require.NoError(t, err)
			require.Equal(t, "localhost:3000", callback.Host)
			require.Equal(t, "kept", callback.Query().Get("existing"))
			require.Equal(t, p.Get("state"), callback.Query().Get("state"))
			require.Len(t, callback.Query()["code"], 1)
			code, err := authcode.AuthCodeByCodeIncludingUsed(callback.Query().Get("code"))
			require.NoError(t, err)
			require.Equal(t, "test-client", code.ClientID)
			require.Equal(t, testCodeChallenge, code.CodeChallenge)
			tokens := exchangeCode(t, ts, code.Code, redirect, "test-client", testCodeVerifier)
			require.NotEmpty(t, tokens.AccessToken)
		})
	}
}

// RFC 6749 §4.1.3: a legacy code with no client binding cannot be exchanged,
// either anonymously or by supplying an otherwise valid registered client.
func TestAuthCode_RejectsUnboundCode(t *testing.T) {
	ts := startTestServer(t)
	usr := createTestUser(t, "unbound", "password123", "unbound@example.com")
	require.NoError(t, authcode.CreateAuthCode(authcode.AuthCode{
		Code: "unbound-code", UserID: usr.ID, RedirectURI: "http://localhost:3000/callback",
		Scope: "openid", ExpiresAt: time.Now().Add(time.Minute),
	}))
	for _, clientID := range []string{"", "test-client"} {
		exchangeCodeExpectError(t, ts, "unbound-code", "http://localhost:3000/callback", clientID, "", http.StatusBadRequest, "invalid_grant")
	}
	code, err := authcode.AuthCodeByCodeIncludingUsed("unbound-code")
	require.NoError(t, err)
	require.False(t, code.Used)
	var count int
	require.NoError(t, db.GetDB().QueryRow("SELECT count(*) FROM tokens").Scan(&count))
	require.Zero(t, count)
}
