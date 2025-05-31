package token

import (
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/user"

	"github.com/stretchr/testify/assert"
)

func TestGenerateTokens(t *testing.T) {
	config.Values.AuthAccessTokenExpiration = 15 * time.Minute
	config.Values.AuthRefreshTokenExpiration = 30 * 24 * time.Hour
	config.Values.AuthAccessTokenSecret = "test-secret"
	config.Values.AuthRefreshTokenSecret = "test-secret"

	testUser := user.User{
		ID:       "user-1",
		Username: "testuser",
		Email:    "testuser@example.com",
	}

	tokens, err := GenerateTokens(testUser)
	assert.NoError(t, err)
	assert.NotEmpty(t, tokens.AccessToken)
	assert.NotEmpty(t, tokens.RefreshToken)
	assert.Equal(t, testUser.ID, tokens.UserID)
	assert.WithinDuration(t, time.Now().Add(config.Values.AuthAccessTokenExpiration), tokens.AccessExpiresAt, time.Minute)
	assert.WithinDuration(t, time.Now().Add(config.Values.AuthRefreshTokenExpiration), tokens.RefreshExpiresAt, time.Minute)
}
