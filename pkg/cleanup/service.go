package cleanup

import (
	"context"
	"fmt"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
)

// Run deletes expired records older than the retention threshold from all
// transient tables. It is safe to call concurrently and is idempotent.
func Run(retention time.Duration) {
	threshold := time.Now().Add(-retention)

	queries := []struct {
		table string
		sql   string
	}{
		{"auth_codes", `DELETE FROM auth_codes WHERE expires_at < ?`},
		{"mfa_challenges", `DELETE FROM mfa_challenges WHERE expires_at < ?`},
		{"passkey_challenges", `DELETE FROM passkey_challenges WHERE expires_at < ?`},
		{"trusted_devices", `DELETE FROM trusted_devices WHERE expires_at < ?`},
		{"tokens", `DELETE FROM tokens WHERE refresh_token_expires_at < ?`},
		{"sessions", `DELETE FROM sessions WHERE expires_at < ?`},
		{"idp_sessions", `DELETE FROM idp_sessions WHERE deactivated_at IS NOT NULL AND deactivated_at < ?`},
	}

	for _, q := range queries {
		res, err := db.GetDB().Exec(q.sql, threshold)
		if err != nil {
			fmt.Printf("[cleanup] error cleaning %s: %v\n", q.table, err)
			continue
		}
		n, _ := res.RowsAffected()
		if n > 0 {
			fmt.Printf("[cleanup] deleted %d expired rows from %s\n", n, q.table)
		}
	}
}

// Start launches a background goroutine that calls Run every interval.
// It stops when ctx is cancelled.
func Start(ctx context.Context, interval, retention time.Duration) {
	go func() {
		// Run once immediately on startup to clean up any backlog.
		Run(retention)

		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				Run(retention)
			case <-ctx.Done():
				return
			}
		}
	}()
}
