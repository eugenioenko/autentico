package session

import (
	"testing"
	"time"

	testutils "github.com/eugenioenko/autentico/tests/utils"

	"github.com/stretchr/testify/assert"
)

func TestSessionByID(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "test-user-id")

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

func TestSessionByID_NotFound(t *testing.T) {
	testutils.WithTestDB(t)

	result, err := SessionByID("nonexistent-session")
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "session not found")
}

func TestSessionByAccessToken(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "test-user-id")

	testSession := Session{
		ID:           "token-session-id",
		UserID:       "test-user-id",
		AccessToken:  "find-by-this-token",
		RefreshToken: "test-refresh-token",
		UserAgent:    "test-user-agent",
		IPAddress:    "127.0.0.1",
		Location:     "test-location",
		ExpiresAt:    time.Now().Add(24 * time.Hour),
	}

	err := CreateSession(testSession)
	assert.NoError(t, err)

	result, err := SessionByAccessToken("find-by-this-token")
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "token-session-id", result.ID)
	assert.Equal(t, "test-user-id", result.UserID)
}

func TestSessionByAccessToken_NotFound(t *testing.T) {
	testutils.WithTestDB(t)

	result, err := SessionByAccessToken("nonexistent-token")
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "session not found")
}

func TestListSessions(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "u1")

	_ = CreateSession(Session{ID: "s1", UserID: "u1", AccessToken: "a1", RefreshToken: "r1", ExpiresAt: time.Now().Add(time.Hour)})
	_ = CreateSession(Session{ID: "s2", UserID: "u1", AccessToken: "a2", RefreshToken: "r2", ExpiresAt: time.Now().Add(time.Hour)})

	sessions, err := ListSessions()
	assert.NoError(t, err)
	assert.Len(t, sessions, 2)
}

func TestListSessionsByUser(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "u1")
	testutils.InsertTestUser(t, "u2")

	_ = CreateSession(Session{ID: "s1", UserID: "u1", AccessToken: "a1", RefreshToken: "r1", ExpiresAt: time.Now().Add(time.Hour)})
	_ = CreateSession(Session{ID: "s2", UserID: "u2", AccessToken: "a2", RefreshToken: "r2", ExpiresAt: time.Now().Add(time.Hour)})

	sessions, err := ListSessionsByUser("u1")
	assert.NoError(t, err)
	assert.Len(t, sessions, 1)
	assert.Equal(t, "s1", sessions[0].ID)
}

func TestDeactivateSessionByID(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "u1")

	_ = CreateSession(Session{ID: "s1", UserID: "u1", AccessToken: "a1", RefreshToken: "r1", ExpiresAt: time.Now().Add(time.Hour)})

	err := DeactivateSessionByID("s1")
	assert.NoError(t, err)

	s, err := SessionByID("s1")
	assert.NoError(t, err)
	assert.NotNil(t, s.DeactivatedAt)
}

func TestToResponse(t *testing.T) {
	deactivatedAt := time.Now()
	s := Session{
		ID:            "s1",
		UserID:        "u1",
		UserAgent:     "ua",
		IPAddress:     "1.1.1.1",
		Location:      "loc",
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(time.Hour),
		DeactivatedAt: &deactivatedAt,
	}
	resp := s.ToResponse()
	assert.Equal(t, s.ID, resp.ID)
	assert.Equal(t, s.UserAgent, resp.UserAgent)
	assert.NotNil(t, resp.DeactivatedAt)
}
