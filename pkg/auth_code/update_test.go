package authcode

import (
	"testing"

	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMarkAuthCodeAsUsed(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user-1")

	// Insert a test auth code
	_, err := db.GetDB().Exec(`
		INSERT INTO auth_codes (code, user_id, redirect_uri, scope, expires_at, used, created_at)
		VALUES ('test-code', 'user-1', 'http://localhost/callback', 'read', DATETIME('now', '+1 hour'), FALSE, DATETIME('now'))
	`)
	assert.NoError(t, err)

	// Mark the auth code as used
	err = MarkAuthCodeAsUsed("test-code")
	assert.NoError(t, err)

	// Verify the auth code is marked as used
	var used bool
	err = db.GetDB().QueryRow(`SELECT used FROM auth_codes WHERE code = 'test-code'`).Scan(&used)
	assert.NoError(t, err)
	assert.True(t, used)
}

func TestMarkAuthCodeAsUsed_NonExistentCode(t *testing.T) {
	testutils.WithTestDB(t)

	// Zero affected rows cannot authorize a redemption.
	err := MarkAuthCodeAsUsed("non-existent-code")
	assert.ErrorIs(t, err, ErrCodeUsed)
}

func TestMarkAuthCodeAsUsed_ConcurrentSingleWinner(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "race-user")
	_, err := db.GetDB().Exec(`INSERT INTO auth_codes (code,user_id,redirect_uri,expires_at) VALUES ('race-code','race-user','http://localhost/callback',datetime('now','+1 hour'))`)
	require.NoError(t, err)
	start := make(chan struct{})
	results := make(chan error, 20)
	for i := 0; i < cap(results); i++ {
		go func() { <-start; results <- MarkAuthCodeAsUsed("race-code") }()
	}
	close(start)
	wins := 0
	for i := 0; i < cap(results); i++ {
		err := <-results
		if err == nil {
			wins++
		} else {
			require.ErrorIs(t, err, ErrCodeUsed)
		}
	}
	require.Equal(t, 1, wins)
}
