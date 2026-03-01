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

func TestHandleSessionAdminEndpoint(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user1")
	testutils.InsertTestUser(t, "user2")

	// Create some test sessions
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

	// Test GET /admin/api/sessions (list all)
	req := httptest.NewRequest(http.MethodGet, "/admin/api/sessions", nil)
	rr := httptest.NewRecorder()
	HandleSessionAdminEndpoint(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp model.ApiResponse[[]SessionResponse]
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Len(t, resp.Data, 2)

	// Test GET /admin/api/sessions?user_id=user1
	req = httptest.NewRequest(http.MethodGet, "/admin/api/sessions?user_id=user1", nil)
	rr = httptest.NewRecorder()
	HandleSessionAdminEndpoint(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	err = json.Unmarshal(rr.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Len(t, resp.Data, 1)
	assert.Equal(t, "sess1", resp.Data[0].ID)

	// Test DELETE /admin/api/sessions?id=sess1
	req = httptest.NewRequest(http.MethodDelete, "/admin/api/sessions?id=sess1", nil)
	rr = httptest.NewRecorder()
	HandleSessionAdminEndpoint(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	
	// Verify deactivated
	s, _ := SessionByID("sess1")
	assert.NotNil(t, s.DeactivatedAt)

	// Test DELETE without id
	req = httptest.NewRequest(http.MethodDelete, "/admin/api/sessions", nil)
	rr = httptest.NewRecorder()
	HandleSessionAdminEndpoint(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	// Test invalid method
	req = httptest.NewRequest(http.MethodPost, "/admin/api/sessions", nil)
	rr = httptest.NewRecorder()
	HandleSessionAdminEndpoint(rr, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}
