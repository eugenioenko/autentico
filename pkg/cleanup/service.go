package cleanup

import (
	"context"
	"fmt"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
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
		{"password_reset_tokens", `DELETE FROM password_reset_tokens WHERE expires_at < ?`},
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

	// Audit log cleanup uses its own retention setting.
	// "0"/empty = disabled, "-1" = keep forever, otherwise parse as duration.
	auditRetention := config.Get().AuditLogRetentionStr
	if auditRetention != "" && auditRetention != "0" && auditRetention != "-1" {
		if d, err := time.ParseDuration(auditRetention); err == nil {
			auditThreshold := time.Now().Add(-d)
			res, err := db.GetDB().Exec(`DELETE FROM audit_logs WHERE created_at < ?`, auditThreshold)
			if err != nil {
				fmt.Printf("[cleanup] error cleaning audit_logs: %v\n", err)
			} else if n, _ := res.RowsAffected(); n > 0 {
				fmt.Printf("[cleanup] deleted %d expired rows from audit_logs\n", n)
			}
		}
	}
}

// Start launches a background goroutine that calls Run every interval.
// Optional hooks are called on every tick alongside the DB cleanup.
// It stops when ctx is cancelled.
func Start(ctx context.Context, interval, retention time.Duration, hooks ...func()) {
	runAll := func() {
		Run(retention)
		for _, h := range hooks {
			h()
		}
	}

	go func() {
		// Run once immediately on startup to clean up any backlog.
		runAll()

		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				runAll()
			case <-ctx.Done():
				return
			}
		}
	}()
}
