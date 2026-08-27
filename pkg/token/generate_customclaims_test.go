package token

import (
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/key"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/userclaim"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateIDToken_CustomClaims(t *testing.T) {
	testutils.WithTestDB(t)
	config.Values.AuthAccessTokenExpiration = 15 * time.Minute
	config.Bootstrap.AppAuthIssuer = "http://localhost/oauth2"

	testutils.InsertTestUser(t, "user-cc-1")
	require.NoError(t, userclaim.UpsertClaim("user-cc-1", "tier", "gold"))
	require.NoError(t, userclaim.UpsertClaim("user-cc-1", "region", "eu"))

	testUser := user.User{ID: "user-cc-1", Username: "testuser"}

	idToken, err := GenerateIDToken(testUser, "session-1", "", "openid custom_claims", "my-client", time.Now(), "fake-access-token")
	require.NoError(t, err)

	claims := parseIDTokenClaims(t, idToken)
	assert.Equal(t, "gold", claims["tier"])
	assert.Equal(t, "eu", claims["region"])
}

func TestGenerateIDToken_NoCustomClaimsScope(t *testing.T) {
	testutils.WithTestDB(t)
	config.Values.AuthAccessTokenExpiration = 15 * time.Minute
	config.Bootstrap.AppAuthIssuer = "http://localhost/oauth2"

	testutils.InsertTestUser(t, "user-cc-2")
	require.NoError(t, userclaim.UpsertClaim("user-cc-2", "tier", "gold"))

	testUser := user.User{ID: "user-cc-2", Username: "testuser"}

	idToken, err := GenerateIDToken(testUser, "session-1", "", "openid profile", "my-client", time.Now(), "fake-access-token")
	require.NoError(t, err)

	claims := parseIDTokenClaims(t, idToken)
	assert.Nil(t, claims["tier"], "custom claims must be absent without the custom_claims scope")
}

func TestGenerateTokens_CustomClaims(t *testing.T) {
	testutils.WithTestDB(t)
	config.Values.AuthAccessTokenExpiration = 15 * time.Minute
	config.Bootstrap.AuthRefreshTokenSecret = "test-secret"
	config.Bootstrap.AppAuthIssuer = "http://localhost/oauth2"

	testutils.InsertTestUser(t, "user-cc-3")
	require.NoError(t, userclaim.UpsertClaim("user-cc-3", "tier", "gold"))

	testUser := user.User{ID: "user-cc-3", Username: "testuser", Email: "test@example.com"}

	tokens, err := GenerateTokens(testUser, "", "openid custom_claims", config.Get())
	require.NoError(t, err)

	claims := parseAccessTokenClaims(t, tokens.AccessToken)
	assert.Equal(t, "gold", claims["tier"])
}

func TestGenerateTokens_CustomClaimsCannotOverrideStandardClaim(t *testing.T) {
	testutils.WithTestDB(t)
	config.Values.AuthAccessTokenExpiration = 15 * time.Minute
	config.Bootstrap.AuthRefreshTokenSecret = "test-secret"
	config.Bootstrap.AppAuthIssuer = "http://localhost/oauth2"

	testutils.InsertTestUser(t, "user-cc-4")
	require.NoError(t, userclaim.UpsertClaim("user-cc-4", "tier", "gold"))
	// Bypass write-time validation by inserting directly, simulating a legacy/tampered row.
	_, err := db.GetDB().Exec(`INSERT INTO user_claims (user_id, claim_name, claim_value) VALUES (?, ?, ?)`, "user-cc-4", "sub", "evil")
	require.NoError(t, err)

	testUser := user.User{ID: "user-cc-4", Username: "testuser"}

	tokens, err := GenerateTokens(testUser, "", "openid custom_claims", config.Get())
	require.NoError(t, err)

	claims := parseAccessTokenClaims(t, tokens.AccessToken)
	assert.Equal(t, "user-cc-4", claims["sub"], "custom claim must never override the real sub")
	assert.Equal(t, "gold", claims["tier"])
}

func TestGenerateIDToken_CustomClaimsCannotOverrideStandardClaim(t *testing.T) {
	testutils.WithTestDB(t)
	config.Values.AuthAccessTokenExpiration = 15 * time.Minute
	config.Bootstrap.AppAuthIssuer = "http://localhost/oauth2"

	testutils.InsertTestUser(t, "user-cc-id-override")
	// Direct insert bypasses write-time reserved-name rejection.
	_, err := db.GetDB().Exec(`INSERT INTO user_claims (user_id, claim_name, claim_value) VALUES (?, ?, ?)`,
		"user-cc-id-override", "sub", "evil")
	require.NoError(t, err)
	_, err = db.GetDB().Exec(`INSERT INTO user_claims (user_id, claim_name, claim_value) VALUES (?, ?, ?)`,
		"user-cc-id-override", "iss", "https://evil.example.com")
	require.NoError(t, err)

	testUser := user.User{ID: "user-cc-id-override", Username: "testuser"}

	idToken, err := GenerateIDToken(testUser, "session-1", "", "openid custom_claims", "my-client", time.Now(), "at")
	require.NoError(t, err)

	claims := parseIDTokenClaims(t, idToken)
	assert.Equal(t, "user-cc-id-override", claims["sub"], "custom claim must never override the real sub")
	assert.Equal(t, "http://localhost/oauth2", claims["iss"], "custom claim must never override the real iss")
}

func TestGenerateIDToken_NamespacedCustomClaimName(t *testing.T) {
	testutils.WithTestDB(t)
	config.Values.AuthAccessTokenExpiration = 15 * time.Minute
	config.Bootstrap.AppAuthIssuer = "http://localhost/oauth2"

	testutils.InsertTestUser(t, "user-cc-ns")
	const name = "https://claims.example.com/tier"
	require.NoError(t, userclaim.UpsertClaim("user-cc-ns", name, "gold"))

	testUser := user.User{ID: "user-cc-ns", Username: "testuser"}

	idToken, err := GenerateIDToken(testUser, "session-1", "", "openid custom_claims", "my-client", time.Now(), "at")
	require.NoError(t, err)

	claims := parseIDTokenClaims(t, idToken)
	assert.Equal(t, "gold", claims[name], "namespaced claim name must appear verbatim as the JWT claim key")
}

func TestGenerateIDToken_CustomClaimValueStaysLiteralString(t *testing.T) {
	testutils.WithTestDB(t)
	config.Values.AuthAccessTokenExpiration = 15 * time.Minute
	config.Bootstrap.AppAuthIssuer = "http://localhost/oauth2"

	testutils.InsertTestUser(t, "user-cc-json")
	require.NoError(t, userclaim.UpsertClaim("user-cc-json", "meta", `{"x":1}`))

	testUser := user.User{ID: "user-cc-json", Username: "testuser"}

	idToken, err := GenerateIDToken(testUser, "session-1", "", "openid custom_claims", "my-client", time.Now(), "at")
	require.NoError(t, err)

	claims := parseIDTokenClaims(t, idToken)
	assert.Equal(t, `{"x":1}`, claims["meta"], "custom claim values are always literal strings, never parsed")
}

func TestGenerateClientCredentialsToken_NoCustomClaims(t *testing.T) {
	testutils.WithTestDB(t)
	config.Values.AuthAccessTokenExpiration = 15 * time.Minute
	config.Bootstrap.AppAuthIssuer = "http://localhost/oauth2"

	tok, err := GenerateClientCredentialsToken("my-client", "openid custom_claims", config.Get())
	require.NoError(t, err)

	claims := parseAccessTokenClaims(t, tok.AccessToken)
	// client_credentials has no resource owner; only the fixed claim set is present.
	for k := range claims {
		assert.Contains(t,
			[]string{"exp", "iat", "auth_time", "jti", "iss", "aud", "sub", "typ", "azp", "sid", "acr", "scope"},
			k, "unexpected claim %q in client_credentials token", k)
	}
}

func parseAccessTokenClaims(t *testing.T, token string) jwt.MapClaims {
	t.Helper()
	parsed, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return key.GetPublicKey(), nil
	})
	require.NoError(t, err)
	return parsed.Claims.(jwt.MapClaims)
}
