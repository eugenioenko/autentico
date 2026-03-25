package idpsession

import (
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"

	"github.com/stretchr/testify/assert"
)

func TestIdpSessionByID(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user-1")

	session := IdpSession{
		ID:        "idp-read-1",
		UserID:    "user-1",
		UserAgent: "test-agent",
		IPAddress: "127.0.0.1",
	}
	err := CreateIdpSession(session)
	assert.NoError(t, err)

	result, err := IdpSessionByID("idp-read-1")
	assert.NoError(t, err)
	assert.Equal(t, "idp-read-1", result.ID)
	assert.Equal(t, "user-1", result.UserID)
	assert.Equal(t, "test-agent", result.UserAgent)
	assert.Equal(t, "127.0.0.1", result.IPAddress)
}

func TestIdpSessionByID_TimestampsRoundTrip(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user-1")

	before := time.Now().Add(-time.Second)
	session := IdpSession{
		ID:     "idp-timestamps-1",
		UserID: "user-1",
	}
	err := CreateIdpSession(session)
	assert.NoError(t, err)

	result, err := IdpSessionByID("idp-timestamps-1")
	assert.NoError(t, err)
	assert.False(t, result.CreatedAt.IsZero(), "CreatedAt must not be zero")
	assert.False(t, result.LastActivityAt.IsZero(), "LastActivityAt must not be zero")
	assert.True(t, result.CreatedAt.After(before), "CreatedAt must be recent")
	assert.True(t, result.LastActivityAt.After(before), "LastActivityAt must be recent")
}

func TestIdpSessionByID_NotFound(t *testing.T) {
	testutils.WithTestDB(t)

	result, err := IdpSessionByID("nonexistent")
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "idp session not found")
}

func TestIdpSessionByID_Deactivated(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user-1")

	session := IdpSession{
		ID:        "idp-deactivated-1",
		UserID:    "user-1",
		UserAgent: "test-agent",
		IPAddress: "127.0.0.1",
	}
	err := CreateIdpSession(session)
	assert.NoError(t, err)

	// Deactivate the session
	_, err = db.GetDB().Exec(`UPDATE idp_sessions SET deactivated_at = CURRENT_TIMESTAMP WHERE id = 'idp-deactivated-1'`)
	assert.NoError(t, err)

	// Should not find deactivated session
	result, err := IdpSessionByID("idp-deactivated-1")
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "idp session not found")
}
