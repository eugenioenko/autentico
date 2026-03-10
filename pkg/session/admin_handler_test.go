package session

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/model"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
)

func TestHandleListSessions(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user1")
	testutils.InsertTestUser(t, "user2")

	s1 := Session{
		ID:           "sess1",
		UserID:       "user1",
		AccessToken:  "at1",
		RefreshToken: "rt1",
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	s2 := Session{
		ID:           "sess2",
		UserID:       "user2",
		AccessToken:  "at2",
		RefreshToken: "rt2",
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	_ = CreateSession(s1)
	_ = CreateSession(s2)

	// List all
	req := httptest.NewRequest(http.MethodGet, "/admin/api/sessions", nil)
	rr := httptest.NewRecorder()
	HandleListSessions(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp model.ApiResponse[[]SessionResponse]
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Len(t, resp.Data, 2)

	// Filter by user_id
	req = httptest.NewRequest(http.MethodGet, "/admin/api/sessions?user_id=user1", nil)
	rr = httptest.NewRecorder()
	HandleListSessions(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	err = json.Unmarshal(rr.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Len(t, resp.Data, 1)
	assert.Equal(t, "sess1", resp.Data[0].ID)
}

func TestHandleDeactivateSession(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user1")

	s := Session{
		ID:           "sess1",
		UserID:       "user1",
		AccessToken:  "at1",
		RefreshToken: "rt1",
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	_ = CreateSession(s)

	req := httptest.NewRequest(http.MethodDelete, "/admin/api/sessions/sess1", nil)
	req.SetPathValue("id", "sess1")
	rr := httptest.NewRecorder()
	HandleDeactivateSession(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	sess, _ := SessionByID("sess1")
	assert.NotNil(t, sess.DeactivatedAt)
}

func TestHandleDeactivateSession_MissingID(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodDelete, "/admin/api/sessions/", nil)
	rr := httptest.NewRecorder()
	HandleDeactivateSession(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}
