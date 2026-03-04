package mfa

import (
	"testing"
	"time"

	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
)

func TestMarkChallengeUsed(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "u1")
	
	c := MfaChallenge{
		ID:         "c1",
		UserID:     "u1",
		Method:     "totp",
		LoginState: "{}",
		ExpiresAt:  time.Now().Add(time.Hour),
	}
	_ = CreateMfaChallenge(c)

	err := MarkChallengeUsed("c1")
	assert.NoError(t, err)

	retrieved, err := MfaChallengeByID("c1")
	assert.NoError(t, err)
	assert.True(t, retrieved.Used)
}

func TestUpdateChallengeCode(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "u1")
	
	c := MfaChallenge{
		ID:         "c1",
		UserID:     "u1",
		Method:     "email",
		LoginState: "{}",
		ExpiresAt:  time.Now().Add(time.Hour),
	}
	_ = CreateMfaChallenge(c)

	err := UpdateChallengeCode("c1", "new-code")
	assert.NoError(t, err)

	retrieved, err := MfaChallengeByID("c1")
	assert.NoError(t, err)
	assert.Equal(t, "new-code", retrieved.Code)
}
