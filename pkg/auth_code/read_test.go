package authcode

import (
	"testing"

	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"

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

func TestAuthCodeByCode_NotFound(t *testing.T) {
	testutils.WithTestDB(t)

	authCode, err := AuthCodeByCode("non-existent-code")
	assert.Error(t, err)
	assert.Nil(t, authCode)
	assert.Contains(t, err.Error(), "authorization code not found")
}

func TestAuthCodeByCode_WithClientID(t *testing.T) {
	testutils.WithTestDB(t)

	// Insert a test auth code with client_id
	_, err := db.GetDB().Exec(`
		INSERT INTO auth_codes (code, user_id, client_id, redirect_uri, scope, expires_at, used, created_at)
		VALUES ('code-with-client', 'user-1', 'client-123', 'http://localhost/callback', 'read', DATETIME('now', '+1 hour'), FALSE, DATETIME('now'))
	`)
	assert.NoError(t, err)

	authCode, err := AuthCodeByCode("code-with-client")
	assert.NoError(t, err)
	assert.Equal(t, "code-with-client", authCode.Code)
	assert.Equal(t, "client-123", authCode.ClientID)
}
