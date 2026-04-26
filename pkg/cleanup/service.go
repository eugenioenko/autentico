package cleanup

import (
	"context"
	"log/slog"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/idpsession"
)

// Run deletes expired records older than the retention threshold from all
// transient tables. It is safe to call concurrently and is idempotent.
func Run(retention time.Duration) {
	deactivateIdleIdpSessions()
	deactivateExpiredMaxAgeIdpSessions()
	deleteExpiredTransientRows(time.Now().Add(-retention))
	deleteExpiredAuditLogs()
}

var transientTables = []struct {
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

func deleteExpiredTransientRows(threshold time.Time) {
	for _, q := range transientTables {
		res, err := db.GetWriteDB().Exec(q.sql, threshold)
		if err != nil {
			slog.Error("cleanup: failed to clean table", "table", q.table, "error", err)
			continue
		}
		n, _ := res.RowsAffected()
		if n > 0 {
			slog.Info("cleanup: deleted expired rows", "table", q.table, "count", n)
		}
	}
}

func deleteExpiredAuditLogs() {
	retention := config.Get().AuditLogRetentionStr
	if retention == "" || retention == "0" || retention == "-1" {
		return
	}
	d, err := time.ParseDuration(retention)
	if err != nil {
		return
	}
	res, err := db.GetWriteDB().Exec(`DELETE FROM audit_logs WHERE created_at < ?`, time.Now().Add(-d))
	if err != nil {
		slog.Error("cleanup: failed to clean table", "table", "audit_logs", "error", err)
		return
	}
	if n, _ := res.RowsAffected(); n > 0 {
		slog.Info("cleanup: deleted expired rows", "table", "audit_logs", "count", n)
	}
}

func deactivateIdleIdpSessions() {
	idle := config.Get().AuthSsoSessionIdleTimeout
	if idle <= 0 {
		return
	}
	n, err := idpsession.DeactivateIdle(idle)
	if err != nil {
		slog.Error("cleanup: failed to deactivate idle idp_sessions", "error", err)
		return
	}
	if n > 0 {
		slog.Info("cleanup: deactivated idle idp_sessions", "count", n)
	}
}

func deactivateExpiredMaxAgeIdpSessions() {
	maxAge := config.Get().AuthSsoSessionMaxAge
	if maxAge <= 0 {
		return
	}
	n, err := idpsession.DeactivateExpiredMaxAge(maxAge)
	if err != nil {
		slog.Error("cleanup: failed to deactivate expired max-age idp_sessions", "error", err)
		return
	}
	if n > 0 {
		slog.Info("cleanup: deactivated expired max-age idp_sessions", "count", n)
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
