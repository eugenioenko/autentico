package devicecode

import (
	"testing"
	"time"

	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestConsumeDeviceCode_ConcurrentSingleWinner(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "device-user")
	testutils.InsertTestClient(t, "device-client", nil)
	require.NoError(t, CreateDeviceCode(DeviceCode{Code: "race-device", UserCode: "RACE-DEVICE", ClientID: "device-client", Status: "pending", ExpiresAt: time.Now().Add(time.Hour)}))
	require.ErrorIs(t, ConsumeDeviceCode("race-device"), ErrCodeConsumed)
	require.ErrorIs(t, ConsumeDeviceCode("missing"), ErrCodeConsumed)
	require.NoError(t, AuthorizeDeviceCode("RACE-DEVICE", "device-user"))
	start := make(chan struct{})
	results := make(chan error, 20)
	for i := 0; i < cap(results); i++ {
		go func() { <-start; results <- ConsumeDeviceCode("race-device") }()
	}
	close(start)
	wins := 0
	for i := 0; i < cap(results); i++ {
		err := <-results
		if err == nil {
			wins++
		} else {
			require.ErrorIs(t, err, ErrCodeConsumed)
		}
	}
	require.Equal(t, 1, wins)
}
