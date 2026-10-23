package appsettings

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eugenioenko/autentico/pkg/model"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestSettingsExportOmitsSecretsAndImportPreservesThem(t *testing.T) {
	for _, password := range []string{"", "configured-smtp-secret"} {
		t.Run(password, func(t *testing.T) {
			testutils.WithTestDB(t)
			testutils.WithConfigOverride(t, func() {})
			require.NoError(t, EnsureDefaults())
			require.NoError(t, SetSetting("smtp_password", password))
			require.NoError(t, SetSetting("private_key", "legacy-private-key"))
			require.NoError(t, SetSetting("smtp_username", "export-user"))
			response := httptest.NewRecorder()
			HandleExportSettings(response, httptest.NewRequest(http.MethodGet, "/admin/api/settings/export", nil))
			require.Equal(t, 200, response.Code)
			var exported model.ApiResponse[settingsExport]
			require.NoError(t, json.Unmarshal(response.Body.Bytes(), &exported))
			require.NotContains(t, exported.Data.Settings, "smtp_password")
			require.NotContains(t, exported.Data.Settings, "private_key")
			require.NotContains(t, exported.Data.Settings, "onboarded")
			require.Equal(t, "export-user", exported.Data.Settings["smtp_username"])
			exported.Data.Settings["smtp_username"] = "import-user"
			payload, err := json.Marshal(exported.Data)
			require.NoError(t, err)
			imported := httptest.NewRecorder()
			HandleImportApply(imported, httptest.NewRequest(http.MethodPost, "/admin/api/settings/import/apply", bytes.NewReader(payload)))
			require.Equal(t, http.StatusNoContent, imported.Code)
			stored, err := GetSetting("smtp_password")
			require.NoError(t, err)
			require.Equal(t, password, stored)
			stored, err = GetSetting("private_key")
			require.NoError(t, err)
			require.Equal(t, "legacy-private-key", stored)
			stored, err = GetSetting("smtp_username")
			require.NoError(t, err)
			require.Equal(t, "import-user", stored)
		})
	}
}
