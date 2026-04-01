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

// --- Export ---

func TestHandleExportSettings_IncludesAllSettings(t *testing.T) {
	testutils.WithTestDB(t)
	_ = SetSetting("smtp_password", "supersecret")
	_ = SetSetting("onboarded", "true")
	_ = SetSetting("theme_title", "My IDP")

	req := httptest.NewRequest(http.MethodGet, "/admin/api/settings/export", nil)
	rr := httptest.NewRecorder()
	HandleExportSettings(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp model.ApiResponse[settingsExport]
	assert.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, 1, resp.Data.Version)
	assert.Equal(t, "My IDP", resp.Data.Settings["theme_title"])
	assert.Equal(t, "supersecret", resp.Data.Settings["smtp_password"])
	assert.NotContains(t, resp.Data.Settings, "onboarded")
}

func TestHandleExportSettings_DatabaseError(t *testing.T) {
	testutils.WithTestDB(t)
	db.CloseDB()

	req := httptest.NewRequest(http.MethodGet, "/admin/api/settings/export", nil)
	rr := httptest.NewRecorder()
	HandleExportSettings(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

// --- Import Preview ---

func TestHandleImportPreview_ReturnsCurrentAndIncoming(t *testing.T) {
	testutils.WithTestDB(t)
	_ = SetSetting("theme_title", "Old Title")

	payload := settingsExport{
		Version:  1,
		Settings: map[string]string{"theme_title": "New Title"},
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/admin/api/settings/import/preview", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	HandleImportPreview(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp model.ApiResponse[settingsPreviewResponse]
	assert.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))

	found := false
	for _, row := range resp.Data.Rows {
		if row.Key == "theme_title" {
			assert.Equal(t, "Old Title", row.Current)
			assert.Equal(t, "New Title", row.Incoming)
			found = true
		}
	}
	assert.True(t, found, "expected theme_title in preview rows")
	assert.Empty(t, resp.Data.Unknown)
}

func TestHandleImportPreview_UnknownKeysReported(t *testing.T) {
	testutils.WithTestDB(t)

	payload := settingsExport{
		Version:  1,
		Settings: map[string]string{"theme_title": "X", "totally_unknown_key": "Y"},
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/admin/api/settings/import/preview", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	HandleImportPreview(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp model.ApiResponse[settingsPreviewResponse]
	assert.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Contains(t, resp.Data.Unknown, "totally_unknown_key")
}

func TestHandleImportPreview_EmptyPayload_ReturnsEmptySlices(t *testing.T) {
	testutils.WithTestDB(t)

	payload := settingsExport{Version: 1, Settings: map[string]string{}}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/admin/api/settings/import/preview", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	HandleImportPreview(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	// Ensure rows and unknown are JSON arrays, not null
	assert.Contains(t, rr.Body.String(), `"rows":[]`)
	assert.Contains(t, rr.Body.String(), `"unknown":[]`)
}

func TestHandleImportPreview_InvalidJSON(t *testing.T) {
	testutils.WithTestDB(t)
	req := httptest.NewRequest(http.MethodPost, "/admin/api/settings/import/preview", bytes.NewBufferString("{bad"))
	rr := httptest.NewRecorder()
	HandleImportPreview(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleImportPreview_DatabaseError(t *testing.T) {
	testutils.WithTestDB(t)
	db.CloseDB()

	payload := settingsExport{Version: 1, Settings: map[string]string{"theme_title": "X"}}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/admin/api/settings/import/preview", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	HandleImportPreview(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

// --- Import Apply ---

func TestHandleImportApply_AppliesKnownKeys(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		_ = SetSetting("theme_title", "Before")

		payload := settingsExport{
			Version:  1,
			Settings: map[string]string{"theme_title": "After"},
		}
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest(http.MethodPost, "/admin/api/settings/import/apply", bytes.NewReader(body))
		rr := httptest.NewRecorder()
		HandleImportApply(rr, req)

		assert.Equal(t, http.StatusNoContent, rr.Code)
		val, _ := GetSetting("theme_title")
		assert.Equal(t, "After", val)
	})
}

func TestHandleImportApply_SkipsProtectedKeys(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		_ = SetSetting("onboarded", "true")

		payload := settingsExport{
			Version:  1,
			Settings: map[string]string{"onboarded": "false", "private_key": "hacked"},
		}
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest(http.MethodPost, "/admin/api/settings/import/apply", bytes.NewReader(body))
		rr := httptest.NewRecorder()
		HandleImportApply(rr, req)

		assert.Equal(t, http.StatusNoContent, rr.Code)
		val, _ := GetSetting("onboarded")
		assert.Equal(t, "true", val)
	})
}

func TestHandleImportApply_SkipsUnknownKeys(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		payload := settingsExport{
			Version:  1,
			Settings: map[string]string{"totally_unknown_key": "value"},
		}
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest(http.MethodPost, "/admin/api/settings/import/apply", bytes.NewReader(body))
		rr := httptest.NewRecorder()
		HandleImportApply(rr, req)

		assert.Equal(t, http.StatusNoContent, rr.Code)
		// key must not have been inserted
		_, err := GetSetting("totally_unknown_key")
		assert.Error(t, err)
	})
}

func TestHandleImportApply_InvalidJSON(t *testing.T) {
	testutils.WithTestDB(t)
	req := httptest.NewRequest(http.MethodPost, "/admin/api/settings/import/apply", bytes.NewBufferString("{bad"))
	rr := httptest.NewRecorder()
	HandleImportApply(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}
