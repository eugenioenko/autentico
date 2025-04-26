package session

import (
	"autentico/pkg/db"
	testutils "autentico/tests/utils"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHandleLogout(t *testing.T) {
	testutils.WithTestDB(t)

	// Insert a test session
	_, err := db.GetDB().Exec(`
		INSERT INTO sessions (id, user_id, access_token, created_at, expires_at)
		VALUES ('session-1', 'user-1', 'access-token', DATETIME('now'), DATETIME('now', '+1 hour'))
	`)
	assert.NoError(t, err)

	// Perform logout
	req := httptest.NewRequest(http.MethodPost, "/oauth2/logout", nil)
	req.Header.Set("Authorization", "Bearer access-token")
	rr := httptest.NewRecorder()

	HandleLogout(rr, req)

	// Verify the response
	assert.Equal(t, http.StatusOK, rr.Code)

	// Verify the session is deactivated
	var deactivatedAt string
	err = db.GetDB().QueryRow(`SELECT deactivated_at FROM sessions WHERE id = 'session-1'`).Scan(&deactivatedAt)
	assert.NoError(t, err)
	assert.NotEmpty(t, deactivatedAt)
}
