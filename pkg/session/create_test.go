package session

import (
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"

	"github.com/stretchr/testify/assert"
)

func TestCreateSession(t *testing.T) {
	testutils.WithTestDB(t)

	session := Session{
		ID:           "session-1",
		UserID:       "user-1",
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		UserAgent:    "test-agent",
		IPAddress:    "127.0.0.1",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	}

	err := CreateSession(session)
	assert.NoError(t, err)

	// Verify the session exists in the database
	var sessionID string
	err = db.GetDB().QueryRow(`SELECT id FROM sessions WHERE id = 'session-1'`).Scan(&sessionID)
	assert.NoError(t, err)
	assert.Equal(t, "session-1", sessionID)
}
