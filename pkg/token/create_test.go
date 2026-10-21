package token

import (
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
	testutils "github.com/eugenioenko/autentico/tests/utils"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ptrStr(s string) *string { return &s }

func TestCreateTokenAcceptsOpaqueCredentialsWithExplicitMetadata(t *testing.T) {
	testutils.WithTestDB(t)
	require.NoError(t, CreateToken(Token{
		AccessToken: "opaque-access", RefreshToken: "opaque-refresh",
		ClientID: "explicit-client", ACR: "2", AccessTokenType: "Bearer",
		AccessTokenExpiresAt:  time.Now().Add(time.Hour),
		RefreshTokenExpiresAt: time.Now().Add(24 * time.Hour), IssuedAt: time.Now(),
		Scope: "read", GrantType: "client_credentials",
	}))
	stored, err := TokenByAccessToken("opaque-access")
	require.NoError(t, err)
	require.Equal(t, "explicit-client", stored.ClientID)
	require.Equal(t, "2", stored.ACR)
	require.Equal(t, utils.HashToken("opaque-refresh"), stored.RefreshTokenHash)
	_, err = TokenByAccessToken(stored.AccessTokenHash)
	require.Error(t, err, "a stored hash is not a bearer credential")
}

func TestCreateToken(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user-1")
	issued, err := GenerateTokens(user.User{ID: "user-1", TotpVerified: true}, "test-client", "read write", config.Get())
	require.NoError(t, err)

	token := Token{
		ClientID:              issued.ClientID,
		ACR:                   issued.ACR,
		UserID:                ptrStr("user-1"),
		AccessToken:           issued.AccessToken,
		RefreshToken:          issued.RefreshToken,
		AccessTokenType:       "Bearer",
		RefreshTokenExpiresAt: time.Now().Add(24 * time.Hour),
		AccessTokenExpiresAt:  time.Now().Add(1 * time.Hour),
		IssuedAt:              time.Now(),
		Scope:                 "read write",
		GrantType:             "password",
	}

	err = CreateToken(token)
	assert.NoError(t, err)

	// Verify the token exists in the database
	var accessToken string
	err = db.GetDB().QueryRow(`SELECT access_token_hash FROM tokens WHERE access_token_hash = ?`, utils.HashToken(issued.AccessToken)).Scan(&accessToken)
	assert.NoError(t, err)
	assert.Equal(t, utils.HashToken(issued.AccessToken), accessToken)
	stored, err := TokenByAccessToken(issued.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, "test-client", stored.ClientID)
	assert.Equal(t, "2", stored.ACR)
	assert.Equal(t, utils.HashToken(issued.RefreshToken), stored.RefreshTokenHash)
	assert.Empty(t, stored.AccessToken)
	assert.Empty(t, stored.RefreshToken)
}

func TestEmptyCredentialCannotMatchClientCredentials(t *testing.T) {
	testutils.WithTestDB(t)
	issued, err := GenerateClientCredentialsToken("service-client", "read", config.Get())
	require.NoError(t, err)
	require.NoError(t, CreateToken(Token{ClientID: issued.ClientID, ACR: issued.ACR, AccessToken: issued.AccessToken, AccessTokenType: "Bearer", AccessTokenExpiresAt: issued.AccessExpiresAt, RefreshTokenExpiresAt: issued.AccessExpiresAt, IssuedAt: time.Now(), Scope: "read", GrantType: "client_credentials"}))
	_, err = TokenByAccessToken("")
	require.Error(t, err)
	require.NoError(t, RevokeByTokenValue(""))
	stored, err := TokenByAccessToken(issued.AccessToken)
	require.NoError(t, err)
	require.Nil(t, stored.RevokedAt)
	require.Empty(t, stored.RefreshTokenHash)
}
