package health

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleHealth_Healthy(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()

	HandleHealth(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp HealthResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "ok", resp.Status)
	assert.Equal(t, "ok", resp.Database)
}

func TestHandleHealth_DatabaseUnavailable(t *testing.T) {
	testutils.WithTestDB(t)
	db.CloseDB()

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()

	HandleHealth(rr, req)

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)

	var resp HealthResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "degraded", resp.Status)
	assert.Equal(t, "unavailable", resp.Database)
}
