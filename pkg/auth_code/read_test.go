package authcode

import (
	"autentico/pkg/db"
	testutils "autentico/tests/utils"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthCodeByCode(t *testing.T) {
	testutils.WithTestDB(t)

	// Insert a test auth code
	_, err := db.GetDB().Exec(`
		INSERT INTO auth_codes (code, user_id, redirect_uri, scope, expires_at, used, created_at)
		VALUES ('test-code', 'user-1', 'http://localhost/callback', 'read', DATETIME('now', '+1 hour'), FALSE, DATETIME('now'))
	`)
	assert.NoError(t, err)

	// Test fetching the auth code
	authCode, err := AuthCodeByCode("test-code")
	assert.NoError(t, err)
	assert.Equal(t, "test-code", authCode.Code)
	assert.Equal(t, "user-1", authCode.UserID)
}
