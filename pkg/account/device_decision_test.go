package account

import (
	"net/http"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/devicecode"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestDeviceDecisionUpdateFailureMapping(t *testing.T) {
	for _, handler := range []struct {
		name   string
		handle http.HandlerFunc
	}{{"authorize", HandleDeviceAuthorize}, {"deny", HandleDeviceDeny}} {
		for _, stale := range []bool{true, false} {
			t.Run(handler.name+map[bool]string{true: "/stale update", false: "/SQL failure"}[stale], func(t *testing.T) {
				testutils.WithTestDB(t)
				_, _, info := setupTestUserAndSession(t)
				require.NoError(t, devicecode.CreateDeviceCode(devicecode.DeviceCode{Code: "device", UserCode: "ABCDEFGH", ClientID: "test", Status: "pending", ExpiresAt: time.Now().Add(time.Hour)}))
				// A trigger forces a zero-row write after the handler has read pending.
				// This deterministically exercises the update-result branch, independently
				// of whether a real HTTP race happens to stop at the earlier precheck.
				action := `SELECT RAISE(IGNORE)`
				if !stale {
					action = `SELECT RAISE(ABORT,'injected decision failure')`
				}
				_, err := db.GetDB().Exec(`CREATE TRIGGER force_decision_result BEFORE UPDATE OF status ON device_codes BEGIN ` + action + `; END`)
				require.NoError(t, err)
				response := mockAuthRequest(t, `{"user_code":"ABCDEFGH"}`, http.MethodPost, "/account/api/device/"+handler.name, handler.handle, info)
				if stale {
					require.Equal(t, http.StatusConflict, response.Code)
					require.Contains(t, response.Body.String(), `"error":"already_used"`)
				} else {
					require.Equal(t, http.StatusInternalServerError, response.Code)
					require.Contains(t, response.Body.String(), `"error":"server_error"`)
				}
				stored, err := devicecode.DeviceCodeByCode("device")
				require.NoError(t, err)
				require.Equal(t, "pending", stored.Status)
				require.Nil(t, stored.UserID)
			})
		}
	}
}
