package security

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/key"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// JWT algorithm confusion and validation tests.
//
// CVE-2022-23539 (Auth0): alg=none accepted
// CVE-2022-23540 (Auth0): RS256→HS256 confusion
// CVE-2022-23541 (Auth0): missing algorithm enforcement
// CVE-2026-23552 (Keycloak): missing issuer claim validation
// CVE-2020-5300 (Hydra): JWT jti claim uniqueness not validated (replay)
// CVE-2020-15222 (Fosite): JWT jti reuse in private_key_jwt client auth
// RFC 9700 §3.2: token must validate aud claim

func forgeJWT(header map[string]any, payload map[string]any, signingFunc func(string) string) string {
	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signingInput := headerB64 + "." + payloadB64
	signature := signingFunc(signingInput)

	return signingInput + "." + signature
}

func callUserinfo(t *testing.T, ts *TestServer, accessToken string) (int, string) {
	t.Helper()
	req, err := http.NewRequest("GET", ts.BaseURL+"/oauth2/userinfo", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(body)
}

// CVE-2022-23539: alg=none — signature stripping attack.
// Server must reject tokens with alg: "none".
func TestJWT_AlgNone_Rejected(t *testing.T) {
	ts := startTestServer(t)
	createTestUser(t, "jwt-user", "password123", "jwt@test.com")

	forgedToken := forgeJWT(
		map[string]any{"alg": "none", "typ": "JWT"},
		map[string]any{
			"sub": "jwt-user",
			"aud": config.GetBootstrap().AppAuthIssuer,
			"iss": config.GetBootstrap().AppAuthIssuer,
			"exp": time.Now().Add(time.Hour).Unix(),
			"iat": time.Now().Unix(),
		},
		func(input string) string { return "" },
	)

	status, _ := callUserinfo(t, ts, forgedToken)
	assert.Equal(t, http.StatusUnauthorized, status,
		"alg=none JWT must be rejected")
}

// CVE-2022-23540: RS256→HS256 algorithm confusion.
// Attacker signs with the public key as HMAC secret.
func TestJWT_AlgConfusion_RS256_to_HS256(t *testing.T) {
	ts := startTestServer(t)
	createTestUser(t, "alg-user", "password123", "alg@test.com")

	pubKey := key.GetPrivateKey().Public().(*rsa.PublicKey)
	pubKeyBytes := pubKey.N.Bytes()

	claims := jwt.MapClaims{
		"sub": "alg-user",
		"aud": config.GetBootstrap().AppAuthIssuer,
		"iss": config.GetBootstrap().AppAuthIssuer,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	forgedToken, err := token.SignedString(pubKeyBytes)
	require.NoError(t, err)

	status, _ := callUserinfo(t, ts, forgedToken)
	assert.Equal(t, http.StatusUnauthorized, status,
		"HS256-signed JWT using public key must be rejected")
}

// CVE-2026-23552: wrong issuer claim must be rejected.
func TestJWT_WrongIssuer_Rejected(t *testing.T) {
	ts := startTestServer(t)
	createTestUser(t, "iss-user", "password123", "iss@test.com")

	claims := jwt.MapClaims{
		"sub": "iss-user",
		"aud": config.GetBootstrap().AppAuthIssuer,
		"iss": "http://evil-issuer.com",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	forgedToken, err := token.SignedString(key.GetPrivateKey())
	require.NoError(t, err)

	status, _ := callUserinfo(t, ts, forgedToken)
	assert.Equal(t, http.StatusUnauthorized, status,
		"JWT with wrong issuer must be rejected")
}

// RFC 9700 §3.2: wrong audience must be rejected.
func TestJWT_WrongAudience_Rejected(t *testing.T) {
	ts := startTestServer(t)
	createTestUser(t, "aud-user", "password123", "aud@test.com")

	claims := jwt.MapClaims{
		"sub": "aud-user",
		"aud": "http://wrong-audience.com",
		"iss": config.GetBootstrap().AppAuthIssuer,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	forgedToken, err := token.SignedString(key.GetPrivateKey())
	require.NoError(t, err)

	status, _ := callUserinfo(t, ts, forgedToken)
	assert.Equal(t, http.StatusUnauthorized, status,
		"JWT with wrong audience must be rejected")
}

// Expired token must be rejected.
func TestJWT_Expired_Rejected(t *testing.T) {
	ts := startTestServer(t)
	createTestUser(t, "exp-user", "password123", "exp@test.com")

	claims := jwt.MapClaims{
		"sub": "exp-user",
		"aud": config.GetBootstrap().AppAuthIssuer,
		"iss": config.GetBootstrap().AppAuthIssuer,
		"exp": time.Now().Add(-time.Hour).Unix(),
		"iat": time.Now().Add(-2 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	forgedToken, err := token.SignedString(key.GetPrivateKey())
	require.NoError(t, err)

	status, _ := callUserinfo(t, ts, forgedToken)
	assert.Equal(t, http.StatusUnauthorized, status,
		"expired JWT must be rejected")
}

// Empty/missing Authorization header.
func TestJWT_MissingAuthHeader(t *testing.T) {
	ts := startTestServer(t)

	req, err := http.NewRequest("GET", ts.BaseURL+"/oauth2/userinfo", nil)
	require.NoError(t, err)

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// Malformed Bearer token.
func TestJWT_MalformedToken(t *testing.T) {
	ts := startTestServer(t)

	tokens := []string{
		"not.a.jwt",
		"Bearer ",
		"eyJhbGciOiJSUzI1NiJ9",
		"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0",
		strings.Repeat("a", 512),
	}

	for _, tok := range tokens {
		t.Run(tok[:min(30, len(tok))], func(t *testing.T) {
			status, _ := callUserinfo(t, ts, tok)
			assert.Equal(t, http.StatusUnauthorized, status,
				"malformed token must be rejected")
		})
	}
}
