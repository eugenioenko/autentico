package token

import (
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"

	"github.com/stretchr/testify/assert"
)

func TestCreateToken(t *testing.T) {
	testutils.WithTestDB(t)

	token := Token{
		UserID:                "user-1",
		AccessToken:           "access-token",
		RefreshToken:          "refresh-token",
		AccessTokenType:       "Bearer",
		RefreshTokenExpiresAt: time.Now().Add(24 * time.Hour),
		AccessTokenExpiresAt:  time.Now().Add(1 * time.Hour),
		IssuedAt:              time.Now(),
		Scope:                 "read write",
		GrantType:             "password",
	}

	err := CreateToken(token)
	assert.NoError(t, err)

	// Verify the token exists in the database
	var accessToken string
	err = db.GetDB().QueryRow(`SELECT access_token FROM tokens WHERE access_token = 'access-token'`).Scan(&accessToken)
	assert.NoError(t, err)
	assert.Equal(t, "access-token", accessToken)
}
