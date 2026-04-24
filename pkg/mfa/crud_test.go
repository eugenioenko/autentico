package mfa

import (
	"testing"
	"time"

	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	read, err := MfaChallengeByIDIncludingExpired("chall1")
	assert.NoError(t, err)
	assert.Equal(t, "user1", read.UserID)
	assert.False(t, read.Used)

	err = UpdateChallengeCode("chall1", "654321")
	assert.NoError(t, err)
	read, _ = MfaChallengeByIDIncludingExpired("chall1")
	assert.Equal(t, "654321", read.Code)

	err = MarkChallengeUsed("chall1")
	assert.NoError(t, err)
	read, _ = MfaChallengeByIDIncludingExpired("chall1")
	assert.True(t, read.Used)
}

func TestMfaChallengeByIDIncludingExpired_ReturnsExpired(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user1")

	c := MfaChallenge{
		ID:         "expired-chall",
		UserID:     "user1",
		Method:     "totp",
		Code:       "123456",
		LoginState: "{}",
		ExpiresAt:  time.Now().Add(-1 * time.Hour),
	}
	require.NoError(t, CreateMfaChallenge(c))

	read, err := MfaChallengeByIDIncludingExpired("expired-chall")
	require.NoError(t, err)
	assert.Equal(t, "expired-chall", read.ID)
	assert.True(t, time.Now().After(read.ExpiresAt))
}

func TestMfaChallengeByIDIncludingExpired_ReturnsUsed(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user1")

	c := MfaChallenge{
		ID:         "used-chall",
		UserID:     "user1",
		Method:     "totp",
		Code:       "123456",
		LoginState: "{}",
		ExpiresAt:  time.Now().Add(time.Hour),
	}
	require.NoError(t, CreateMfaChallenge(c))
	require.NoError(t, MarkChallengeUsed("used-chall"))

	read, err := MfaChallengeByIDIncludingExpired("used-chall")
	require.NoError(t, err)
	assert.Equal(t, "used-chall", read.ID)
	assert.True(t, read.Used)
}
