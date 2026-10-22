package cleanup

import (
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestFederationCleanupUsesExpiryInstantsAndRetention(t *testing.T) {
	testutils.WithTestDB(t)
	threshold := time.Date(2026, 10, 22, 12, 0, 0, 0, time.FixedZone("offset", -7*60*60))
	for _, tc := range []struct {
		id     string
		expiry int64
	}{{"old", threshold.Add(-time.Second).Unix()}, {"boundary", threshold.Unix()}, {"retained", threshold.Add(time.Hour).Unix()}} {
		_, err := db.GetDB().Exec(`INSERT INTO federation_login_flows(flow_id,browser_hash,state_hash,expires_at) VALUES(?,'browser-hash','state-hash',?)`, tc.id, tc.expiry)
		require.NoError(t, err)
	}
	require.NoError(t, cleanFederationFlows(threshold))
	var count int
	require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM federation_login_flows WHERE flow_id='old'`).Scan(&count))
	require.Zero(t, count)
	require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM federation_login_flows`).Scan(&count))
	require.Equal(t, 2, count)
}
