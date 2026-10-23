package devicecode

import (
	"fmt"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestDeviceDecisionSingleWinner(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "decision-user")
	testutils.InsertTestClient(t, "decision-client", nil)
	require.ErrorIs(t, AuthorizeDeviceCode("missing", "decision-user"), ErrCodeConsumed)
	require.ErrorIs(t, DenyDeviceCode("missing"), ErrCodeConsumed)
	for round := 0; round < 40; round++ {
		code := fmt.Sprintf("decision-%d", round)
		require.NoError(t, CreateDeviceCode(DeviceCode{Code: code, UserCode: code, ClientID: "decision-client", Status: "pending", ExpiresAt: time.Now().Add(time.Hour)}))
		type outcome struct {
			status string
			err    error
		}
		start := make(chan struct{})
		results := make(chan outcome, 2)
		go func() { <-start; results <- outcome{"authorized", AuthorizeDeviceCode(code, "decision-user")} }()
		go func() { <-start; results <- outcome{"denied", DenyDeviceCode(code)} }()
		close(start)
		first, second := <-results, <-results
		if first.err != nil {
			first, second = second, first
		}
		require.NoError(t, first.err)
		require.ErrorIs(t, second.err, ErrCodeConsumed)
		stored, err := DeviceCodeByCode(code)
		require.NoError(t, err)
		require.Equal(t, first.status, stored.Status)
		require.ErrorIs(t, AuthorizeDeviceCode(code, "decision-user"), ErrCodeConsumed)
		require.ErrorIs(t, DenyDeviceCode(code), ErrCodeConsumed)
		if first.status == "authorized" {
			require.NoError(t, ConsumeDeviceCode(code))
		} else {
			require.ErrorIs(t, ConsumeDeviceCode(code), ErrCodeConsumed)
		}
	}
}
