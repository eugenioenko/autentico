package appsettings

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
)

func TestIsSafeLinkURL(t *testing.T) {
	valid := []string{
		"/",
		"/account/",
		"/welcome?from=logout",
		"https://app.example.com",
		"https://app.example.com/home",
		"http://localhost:3000/",
		"http://127.0.0.1:8080",
		"http://[::1]:8080/",
	}
	for _, v := range valid {
		assert.True(t, isSafeLinkURL(v), v)
	}

	invalid := []string{
		"javascript:alert(1)",
		"data:text/html,hi",
		"http://app.example.com",
		"ftp://app.example.com",
		"//evil.example.com",
		"/\\evil.example.com",
		"app.example.com",
		"https://user:pass@app.example.com",
		"https://app.example.com/\"onclick=",
		"https://app.example.com/<x>",
		"/path with space",
		"/" + strings.Repeat("a", 2048),
	}
	for _, v := range invalid {
		assert.False(t, isSafeLinkURL(v), v)
	}
}

func TestHandlePutSettings_LogoutSuccessURL(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		body := `{"logout_success_url": "https://app.example.com/", "logout_success_label": "Back to app"}`
		req := httptest.NewRequest(http.MethodPut, "/admin/api/settings", strings.NewReader(body))
		rr := httptest.NewRecorder()
		HandlePutSettings(rr, req)

		assert.Equal(t, http.StatusNoContent, rr.Code)
		assert.Equal(t, "https://app.example.com/", config.Get().LogoutSuccessURL)
		assert.Equal(t, "Back to app", config.Get().LogoutSuccessLabel)
	})
}

func TestHandlePutSettings_LogoutSuccessURLCanBeCleared(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		_ = SetSetting("logout_success_url", "https://app.example.com/")
		body := `{"logout_success_url": ""}`
		req := httptest.NewRequest(http.MethodPut, "/admin/api/settings", strings.NewReader(body))
		rr := httptest.NewRecorder()
		HandlePutSettings(rr, req)

		assert.Equal(t, http.StatusNoContent, rr.Code)
		assert.Equal(t, "", config.Get().LogoutSuccessURL)
	})
}

func TestHandlePutSettings_InvalidLogoutSuccessURL(t *testing.T) {
	testutils.WithTestDB(t)
	body := `{"logout_success_url": "javascript:alert(1)"}`
	req := httptest.NewRequest(http.MethodPut, "/admin/api/settings", strings.NewReader(body))
	rr := httptest.NewRecorder()
	HandlePutSettings(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "logout_success_url")
	val, _ := GetSetting("logout_success_url")
	assert.Equal(t, "", val)
}

func TestHandleImportApply_InvalidLogoutSuccessURL(t *testing.T) {
	testutils.WithTestDB(t)
	payload := settingsExport{
		Version:  1,
		Settings: map[string]string{"logout_success_url": "//evil.example.com"},
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/admin/api/settings/import/apply", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	HandleImportApply(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	val, _ := GetSetting("logout_success_url")
	assert.Equal(t, "", val)
}
