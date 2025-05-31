package authcode

import (
	"testing"

	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"

	"github.com/stretchr/testify/assert"
)

func TestMarkAuthCodeAsUsed(t *testing.T) {
	testutils.WithTestDB(t)

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
