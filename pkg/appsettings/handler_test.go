package appsettings

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/model"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
)

func TestHandleOnboarding(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AppOAuthPath = "/custom-oauth"
	})

	// Case 1: Not onboarded (default in fresh test DB)
	req := httptest.NewRequest(http.MethodGet, "/admin/api/onboarding", nil)
	rr := httptest.NewRecorder()
	HandleOnboarding(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp map[string]any
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, false, resp["onboarded"])
	assert.Equal(t, "/custom-oauth", resp["oauth_path"])

	// Case 2: Onboarded
	_ = SetSetting("onboarded", "true")
	rr = httptest.NewRecorder()
	HandleOnboarding(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	err = json.Unmarshal(rr.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, true, resp["onboarded"])
}

func TestHandleSettings_Get(t *testing.T) {
	testutils.WithTestDB(t)
	_ = SetSetting("test_key", "test_value")
	_ = SetSetting("smtp_password", "secret") // should be omitted

	req := httptest.NewRequest(http.MethodGet, "/admin/api/settings", nil)
	rr := httptest.NewRecorder()
	HandleSettings(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp model.ApiResponse[map[string]string]
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, "test_value", resp.Data["test_key"])
	assert.NotContains(t, resp.Data, "smtp_password")
}

func TestHandleSettings_Put(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		body := `{"access_token_expiration": "60m", "onboarded": "false"}`
		req := httptest.NewRequest(http.MethodPut, "/admin/api/settings", strings.NewReader(body))
		rr := httptest.NewRecorder()
		HandleSettings(rr, req)

		assert.Equal(t, http.StatusNoContent, rr.Code)

		val, _ := GetSetting("access_token_expiration")
		assert.Equal(t, "60m", val)

		// Onboarded should NOT have changed because it's protected
		val, _ = GetSetting("onboarded")
		assert.NotEqual(t, "false", val) // defaults are usually "" in empty test DB if not EnsureDefaults called, but lets say it didn't change to false.
	})
}

func TestHandleSettings_InvalidMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/admin/api/settings", nil)
	rr := httptest.NewRecorder()
	HandleSettings(rr, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}

