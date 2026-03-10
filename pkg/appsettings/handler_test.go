package appsettings

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/model"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
)

func TestHandleGetSettings(t *testing.T) {
	testutils.WithTestDB(t)
	_ = SetSetting("test_key", "test_value")
	_ = SetSetting("smtp_password", "secret") // should be omitted

	req := httptest.NewRequest(http.MethodGet, "/admin/api/settings", nil)
	rr := httptest.NewRecorder()
	HandleGetSettings(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp model.ApiResponse[map[string]string]
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, "test_value", resp.Data["test_key"])
	assert.NotContains(t, resp.Data, "smtp_password")
}

func TestHandlePutSettings(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		body := `{"access_token_expiration": "60m", "onboarded": "false"}`
		req := httptest.NewRequest(http.MethodPut, "/admin/api/settings", strings.NewReader(body))
		rr := httptest.NewRecorder()
		HandlePutSettings(rr, req)

		assert.Equal(t, http.StatusNoContent, rr.Code)

		val, _ := GetSetting("access_token_expiration")
		assert.Equal(t, "60m", val)

		// Onboarded should NOT have changed because it's protected
		val, _ = GetSetting("onboarded")
		assert.NotEqual(t, "false", val)
	})
}

func TestHandlePutSettings_InvalidJSON(t *testing.T) {
	testutils.WithTestDB(t)
	req := httptest.NewRequest(http.MethodPut, "/admin/api/settings", bytes.NewBufferString("{invalid"))
	rr := httptest.NewRecorder()
	HandlePutSettings(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandlePutSettings_DatabaseError(t *testing.T) {
	testutils.WithTestDB(t)

	db.CloseDB()

	body := `{"theme_title": "New Title"}`
	req := httptest.NewRequest(http.MethodPut, "/admin/api/settings", bytes.NewBufferString(body))
	rr := httptest.NewRecorder()
	HandlePutSettings(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestHandleGetSettings_DatabaseError(t *testing.T) {
	testutils.WithTestDB(t)
	db.CloseDB()

	req := httptest.NewRequest(http.MethodGet, "/admin/api/settings", nil)
	rr := httptest.NewRecorder()
	HandleGetSettings(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}
