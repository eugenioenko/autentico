package cleanup

import (
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

// TestMagicLinkCleanupUsesExpiryInstants preserves live used budgets and removes truly expired rows.
func TestMagicLinkCleanupUsesExpiryInstants(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "magic-budget")
	now := time.Now().UTC()
	for _, tc := range []struct {
		id     string
		expiry time.Time
	}{
		{"live", now.Add(time.Hour).In(time.FixedZone("PST", -12*60*60))},
		{"expired", now.Add(-time.Hour).In(time.FixedZone("FUT", 14*60*60))},
	} {
		_, err := db.GetDB().Exec(`INSERT INTO magic_link_tokens(id,user_id,token_hash,expires_at,used_at,failed_attempts) VALUES(?,'magic-budget',?,?,?,5)`, tc.id, tc.id, tc.expiry, now)
		require.NoError(t, err)
	}
	require.NoError(t, cleanMagicLinkTokens(now))
	require.True(t, rowExists(t, "magic_link_tokens", "id", "live"))
	require.False(t, rowExists(t, "magic_link_tokens", "id", "expired"))
}
