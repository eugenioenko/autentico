package mfa

import (
	"testing"
	"time"

	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
)

func TestMfaChallengeCRUD(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user1")

	c := MfaChallenge{
		ID:         "chall1",
		UserID:     "user1",
		Method:     "totp",
		Code:       "123456",
		LoginState: "{}",
		ExpiresAt:  time.Now().Add(time.Hour),
	}

	err := CreateMfaChallenge(c)
	assert.NoError(t, err)

	read, err := MfaChallengeByID("chall1")
	assert.NoError(t, err)
	assert.Equal(t, "user1", read.UserID)
	assert.False(t, read.Used)

	err = UpdateChallengeCode("chall1", "654321")
	assert.NoError(t, err)
	read, _ = MfaChallengeByID("chall1")
	assert.Equal(t, "654321", read.Code)

	err = MarkChallengeUsed("chall1")
	assert.NoError(t, err)
	read, _ = MfaChallengeByID("chall1")
	assert.True(t, read.Used)
}
