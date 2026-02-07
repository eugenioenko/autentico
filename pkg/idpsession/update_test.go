package idpsession

import (
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"

	"github.com/stretchr/testify/assert"
)

func TestUpdateLastActivity(t *testing.T) {
	testutils.WithTestDB(t)

	session := IdpSession{
		ID:        "idp-activity-1",
		UserID:    "user-1",
		UserAgent: "test-agent",
		IPAddress: "127.0.0.1",
	}
	err := CreateIdpSession(session)
	assert.NoError(t, err)

	// Get initial last_activity_at
	var initialActivity time.Time
	err = db.GetDB().QueryRow(`SELECT last_activity_at FROM idp_sessions WHERE id = 'idp-activity-1'`).Scan(&initialActivity)
	assert.NoError(t, err)

	// Small delay to ensure timestamp difference
	time.Sleep(10 * time.Millisecond)

	err = UpdateLastActivity("idp-activity-1")
	assert.NoError(t, err)

	// Verify last_activity_at was updated
	var updatedActivity time.Time
	err = db.GetDB().QueryRow(`SELECT last_activity_at FROM idp_sessions WHERE id = 'idp-activity-1'`).Scan(&updatedActivity)
	assert.NoError(t, err)
	assert.True(t, !updatedActivity.Before(initialActivity), "last_activity_at should be updated")
}

func TestDeactivateIdpSession(t *testing.T) {
	testutils.WithTestDB(t)

	session := IdpSession{
		ID:        "idp-deactivate-1",
		UserID:    "user-1",
		UserAgent: "test-agent",
		IPAddress: "127.0.0.1",
	}
	err := CreateIdpSession(session)
	assert.NoError(t, err)

	err = DeactivateIdpSession("idp-deactivate-1")
	assert.NoError(t, err)

	// Verify the session is deactivated (not findable by read)
	result, err := IdpSessionByID("idp-deactivate-1")
	assert.Error(t, err)
	assert.Nil(t, result)

	// Verify deactivated_at is set in DB
	var deactivatedAt *time.Time
	err = db.GetDB().QueryRow(`SELECT deactivated_at FROM idp_sessions WHERE id = 'idp-deactivate-1'`).Scan(&deactivatedAt)
	assert.NoError(t, err)
	assert.NotNil(t, deactivatedAt)
}

func TestDeactivateIdpSession_AlreadyDeactivated(t *testing.T) {
	testutils.WithTestDB(t)

	session := IdpSession{
		ID:        "idp-double-deactivate",
		UserID:    "user-1",
		UserAgent: "test-agent",
		IPAddress: "127.0.0.1",
	}
	err := CreateIdpSession(session)
	assert.NoError(t, err)

	err = DeactivateIdpSession("idp-double-deactivate")
	assert.NoError(t, err)

	// Second deactivation should not error (just no rows affected)
	err = DeactivateIdpSession("idp-double-deactivate")
	assert.NoError(t, err)
}
