package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/model"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
)

func TestHandleStats(t *testing.T) {
	testutils.WithTestDB(t)

	// Insert some test data
	d := db.GetDB()
	_, _ = d.Exec("INSERT INTO users (id, username, email) VALUES ('u1', 'user1', 'u1@test.com')")
	_, _ = d.Exec("INSERT INTO clients (id, client_id, client_name, is_active, redirect_uris) VALUES ('c1', 'client1', 'Client 1', TRUE, '[]')")
	_, _ = d.Exec("INSERT INTO idp_sessions (id, user_id) VALUES ('idp1', 'u1')")

	rr := testutils.MockJSONRequest(t, "", "GET", "/admin/api/stats", HandleStats)

	var resp model.ApiResponse[StatsResponse]
	err := json.Unmarshal(rr, &resp)
	assert.NoError(t, err)

	assert.Equal(t, 1, resp.Data.TotalUsers)
	assert.Equal(t, 1, resp.Data.ActiveClients)
	assert.Equal(t, 1, resp.Data.ActiveDevices)
}

func TestHandleStats_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/admin/api/stats", nil)
	rr := httptest.NewRecorder()
	HandleStats(rr, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}
