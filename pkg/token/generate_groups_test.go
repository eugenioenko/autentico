package token

import (
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/key"
	"github.com/eugenioenko/autentico/pkg/user"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateIDToken_GroupsClaim(t *testing.T) {
	testutils.WithTestDB(t)
	config.Values.AuthAccessTokenExpiration = 15 * time.Minute
	config.Bootstrap.AppAuthIssuer = "http://localhost/oauth2"

	testutils.InsertTestUser(t, "user-groups-1")
	testutils.InsertTestGroup(t, "g1", "admins")
	testutils.InsertTestGroup(t, "g2", "editors")
	testutils.InsertTestGroupMembership(t, "user-groups-1", "g1")
	testutils.InsertTestGroupMembership(t, "user-groups-1", "g2")

	testUser := user.User{ID: "user-groups-1", Username: "testuser"}

	idToken, err := GenerateIDToken(testUser, "session-1", "", "openid groups", "my-client", time.Now(), "fake-access-token")
	require.NoError(t, err)

	claims := parseIDTokenClaims(t, idToken)
	groupsClaim, ok := claims["groups"].([]interface{})
	require.True(t, ok, "groups claim must be an array")
	assert.Len(t, groupsClaim, 2)
	assert.Contains(t, groupsClaim, "admins")
	assert.Contains(t, groupsClaim, "editors")
}

func TestGenerateIDToken_NoGroupsScope(t *testing.T) {
	testutils.WithTestDB(t)
	config.Values.AuthAccessTokenExpiration = 15 * time.Minute
	config.Bootstrap.AppAuthIssuer = "http://localhost/oauth2"

	testutils.InsertTestUser(t, "user-nogrpscope")
	testutils.InsertTestGroup(t, "g1", "admins")
	testutils.InsertTestGroupMembership(t, "user-nogrpscope", "g1")

	testUser := user.User{ID: "user-nogrpscope", Username: "testuser"}

	idToken, err := GenerateIDToken(testUser, "session-1", "", "openid profile", "my-client", time.Now(), "fake-access-token")
	require.NoError(t, err)

	claims := parseIDTokenClaims(t, idToken)
	assert.Nil(t, claims["groups"], "groups claim must not be present without groups scope")
}

func TestGenerateIDToken_GroupsScopeButNoGroups(t *testing.T) {
	testutils.WithTestDB(t)
	config.Values.AuthAccessTokenExpiration = 15 * time.Minute
	config.Bootstrap.AppAuthIssuer = "http://localhost/oauth2"

	testutils.InsertTestUser(t, "user-nogroups")

	testUser := user.User{ID: "user-nogroups", Username: "testuser"}

	idToken, err := GenerateIDToken(testUser, "session-1", "", "openid groups", "my-client", time.Now(), "fake-access-token")
	require.NoError(t, err)

	claims := parseIDTokenClaims(t, idToken)
	assert.Nil(t, claims["groups"], "groups claim must be omitted when user has no groups")
}

func TestGenerateTokens_GroupsClaim(t *testing.T) {
	testutils.WithTestDB(t)
	config.Values.AuthAccessTokenExpiration = 15 * time.Minute
	config.Bootstrap.AuthRefreshTokenSecret = "test-secret"
	config.Bootstrap.AppAuthIssuer = "http://localhost/oauth2"

	testutils.InsertTestUser(t, "user-at-groups")
	testutils.InsertTestGroup(t, "g1", "devs")
	testutils.InsertTestGroupMembership(t, "user-at-groups", "g1")

	testUser := user.User{ID: "user-at-groups", Username: "testuser", Email: "test@example.com"}

	tokens, err := GenerateTokens(testUser, "", "openid groups", config.Get())
	require.NoError(t, err)

	parsed, err := jwt.Parse(tokens.AccessToken, func(token *jwt.Token) (interface{}, error) {
		return key.GetPublicKey(), nil
	})
	require.NoError(t, err)
	claims := parsed.Claims.(jwt.MapClaims)

	groupsClaim, ok := claims["groups"].([]interface{})
	require.True(t, ok, "groups claim must be an array in access token")
	assert.Contains(t, groupsClaim, "devs")
}

func TestGenerateTokens_NoGroupsScope(t *testing.T) {
	testutils.WithTestDB(t)
	config.Values.AuthAccessTokenExpiration = 15 * time.Minute
	config.Bootstrap.AuthRefreshTokenSecret = "test-secret"
	config.Bootstrap.AppAuthIssuer = "http://localhost/oauth2"

	testutils.InsertTestUser(t, "user-at-nogrp")
	testutils.InsertTestGroup(t, "g1", "devs")
	testutils.InsertTestGroupMembership(t, "user-at-nogrp", "g1")

	testUser := user.User{ID: "user-at-nogrp", Username: "testuser", Email: "test@example.com"}

	tokens, err := GenerateTokens(testUser, "", "openid profile", config.Get())
	require.NoError(t, err)

	parsed, err := jwt.Parse(tokens.AccessToken, func(token *jwt.Token) (interface{}, error) {
		return key.GetPublicKey(), nil
	})
	require.NoError(t, err)
	claims := parsed.Claims.(jwt.MapClaims)

	assert.Nil(t, claims["groups"], "groups claim must not be in access token without groups scope")
}
