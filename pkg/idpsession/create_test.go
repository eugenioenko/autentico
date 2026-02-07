package idpsession

import (
	"testing"

	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"

	"github.com/stretchr/testify/assert"
)

func TestCreateIdpSession(t *testing.T) {
	testutils.WithTestDB(t)

	session := IdpSession{
		ID:        "idp-session-1",
		UserID:    "user-1",
		UserAgent: "test-agent",
		IPAddress: "127.0.0.1",
	}

	err := CreateIdpSession(session)
	assert.NoError(t, err)

	// Verify the session exists in the database
	var sessionID string
	err = db.GetDB().QueryRow(`SELECT id FROM idp_sessions WHERE id = 'idp-session-1'`).Scan(&sessionID)
	assert.NoError(t, err)
	assert.Equal(t, "idp-session-1", sessionID)
}

func TestCreateIdpSession_Duplicate(t *testing.T) {
	testutils.WithTestDB(t)

	session := IdpSession{
		ID:        "idp-session-dup",
		UserID:    "user-1",
		UserAgent: "test-agent",
		IPAddress: "127.0.0.1",
	}

	err := CreateIdpSession(session)
	assert.NoError(t, err)

	// Attempt to create the same session again should fail (primary key)
	err = CreateIdpSession(session)
	assert.Error(t, err)
}
