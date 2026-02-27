package appsettings

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
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
