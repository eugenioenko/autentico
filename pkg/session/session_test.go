package session

import (
	testutils "autentico/tests/utils"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSessionByID(t *testing.T) {
	testutils.WithTestDB(t)

	testSession := Session{
		ID:           "test-session-id",
		UserID:       "test-user-id",
		AccessToken:  "test-access-token",
		RefreshToken: "test-refresh-token",
		UserAgent:    "test-user-agent",
		IPAddress:    "127.0.0.1",
		Location:     "test-location",
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(24 * time.Hour),
	}

	err := CreateSession(testSession)
	assert.NoError(t, err, "failed to create test session")

	// Test: Retrieve the session by ID
	retrievedSession, err := SessionByID("test-session-id")
	assert.NoError(t, err, "failed to retrieve session by ID")
	assert.NotNil(t, retrievedSession, "retrieved session is nil")

	// Validate the retrieved session
	assert.Equal(t, testSession.ID, retrievedSession.ID)
	assert.Equal(t, testSession.UserID, retrievedSession.UserID)
	assert.Equal(t, testSession.AccessToken, retrievedSession.AccessToken)
	assert.Equal(t, testSession.RefreshToken, retrievedSession.RefreshToken)
	assert.Equal(t, testSession.UserAgent, retrievedSession.UserAgent)
	assert.Equal(t, testSession.IPAddress, retrievedSession.IPAddress)
	assert.Equal(t, testSession.Location, retrievedSession.Location)
	assert.WithinDuration(t, testSession.CreatedAt, retrievedSession.CreatedAt, time.Second)
	assert.WithinDuration(t, testSession.ExpiresAt, retrievedSession.ExpiresAt, time.Second)
}
