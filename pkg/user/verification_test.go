package user

import (
	"database/sql"
	"testing"
	"time"

	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetEmailVerificationToken(t *testing.T) {
	testutils.WithTestDB(t)
	u, _ := CreateUser("verifyuser", "password123", "verify@test.com")

	expiresAt := time.Now().Add(24 * time.Hour)
	err := SetEmailVerificationToken(u.ID, "testhash123", expiresAt)
	require.NoError(t, err)

	userID, gotExpiry, err := GetVerificationTokenInfo("testhash123")
	require.NoError(t, err)
	assert.Equal(t, u.ID, userID)
	assert.WithinDuration(t, expiresAt, gotExpiry, time.Second)
}

func TestMarkEmailVerified(t *testing.T) {
	testutils.WithTestDB(t)
	u, _ := CreateUser("verifyuser2", "password123", "verify2@test.com")
	_ = SetEmailVerificationToken(u.ID, "somehash", time.Now().Add(time.Hour))

	err := MarkEmailVerified(u.ID)
	require.NoError(t, err)

	updated, _ := UserByID(u.ID)
	assert.True(t, updated.IsEmailVerified)
}

func TestMarkEmailVerified_ClearsToken(t *testing.T) {
	testutils.WithTestDB(t)
	u, _ := CreateUser("verifyuser3", "password123", "verify3@test.com")
	_ = SetEmailVerificationToken(u.ID, "clearhash", time.Now().Add(time.Hour))

	require.NoError(t, MarkEmailVerified(u.ID))

	// Token should no longer be findable
	_, _, err := GetVerificationTokenInfo("clearhash")
	assert.ErrorIs(t, err, sql.ErrNoRows)
}

func TestGetVerificationTokenInfo_NotFound(t *testing.T) {
	testutils.WithTestDB(t)

	_, _, err := GetVerificationTokenInfo("nonexistent-hash")
	assert.ErrorIs(t, err, sql.ErrNoRows)
}

func TestSetEmailVerificationToken_Overwrite(t *testing.T) {
	testutils.WithTestDB(t)
	u, _ := CreateUser("verifyuser4", "password123", "verify4@test.com")

	_ = SetEmailVerificationToken(u.ID, "oldhash", time.Now().Add(time.Hour))
	_ = SetEmailVerificationToken(u.ID, "newhash", time.Now().Add(2*time.Hour))

	// Old hash is gone
	_, _, err := GetVerificationTokenInfo("oldhash")
	assert.ErrorIs(t, err, sql.ErrNoRows)

	// New hash resolves
	userID, _, err := GetVerificationTokenInfo("newhash")
	require.NoError(t, err)
	assert.Equal(t, u.ID, userID)
}
