package cleanup

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
)

type tokenSessionBinding struct {
	userID, accessHash, refreshHash string
}

// cleanTokenSessions preserves refresh validation and rotation replay evidence
// through the later credential expiry (RFC 6749 §6 / RFC 9700 §4.14.2).
// The writer transaction also repairs pre-fix session metadata before purging.
func cleanTokenSessions(threshold time.Time) error {
	ctx := context.Background()
	conn, err := db.GetWriteDB().Conn(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	lifetimes, expiredTokens, err := tokenLifetimes(tx, threshold)
	if err != nil {
		return err
	}
	rows, err := tx.Query(`SELECT id, COALESCE(user_id, ''), COALESCE(access_token_hash, ''),
		COALESCE(refresh_token_hash, ''), expires_at FROM sessions`)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	type repair struct {
		id     string
		expiry time.Time
	}
	var repairs []repair
	var expiredSessions []string
	for rows.Next() {
		var id string
		var binding tokenSessionBinding
		var storedExpiry sql.NullTime
		if err := rows.Scan(&id, &binding.userID, &binding.accessHash, &binding.refreshHash, &storedExpiry); err != nil {
			return err
		}
		expiry := storedExpiry.Time
		if lifetime, ok := lifetimes[binding]; ok && (!storedExpiry.Valid || lifetime.After(expiry)) {
			expiry = lifetime
			repairs = append(repairs, repair{id, expiry.UTC()})
		}
		if !expiry.IsZero() && expiry.Before(threshold) {
			expiredSessions = append(expiredSessions, id)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	// Read cursors must be closed before writes. Never alter revocation or
	// deactivation: retained evidence must not reactivate an expired login.
	for _, r := range repairs {
		if _, err := tx.Exec(`UPDATE sessions SET expires_at = ? WHERE id = ?`, r.expiry, r.id); err != nil {
			return err
		}
	}
	for _, id := range expiredSessions {
		if _, err := tx.Exec(`DELETE FROM sessions WHERE id = ?`, id); err != nil {
			return err
		}
	}
	for _, id := range expiredTokens {
		if _, err := tx.Exec(`DELETE FROM tokens WHERE id = ?`, id); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		// SQLite can leave a transaction open after a failed COMMIT even
		// though database/sql marks its Tx done. Restore or discard the writer.
		if _, rollbackErr := conn.ExecContext(ctx, "ROLLBACK"); rollbackErr != nil {
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
			return errors.Join(err, rollbackErr)
		}
		return err
	}
	return nil
}

func tokenLifetimes(tx *sql.Tx, threshold time.Time) (map[tokenSessionBinding]time.Time, []string, error) {
	// Include revoked rows: their original sessions are needed to detect replay.
	rows, err := tx.Query(`SELECT id, COALESCE(user_id, ''), access_token_hash, refresh_token_hash,
		access_token_expires_at, refresh_token_expires_at FROM tokens`)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = rows.Close() }()
	lifetimes := make(map[tokenSessionBinding]time.Time)
	var expired []string
	for rows.Next() {
		var id string
		var binding tokenSessionBinding
		var accessExpiry, refreshExpiry time.Time
		if err := rows.Scan(&id, &binding.userID, &binding.accessHash, &binding.refreshHash, &accessExpiry, &refreshExpiry); err != nil {
			return nil, nil, err
		}
		expiry := accessExpiry
		if refreshExpiry.After(expiry) {
			expiry = refreshExpiry
		}
		// Compare parsed instants, not SQLite's lexical timestamp strings:
		// historical rows and retention cutoffs may use different UTC offsets.
		if expiry.Before(threshold) {
			expired = append(expired, id)
		}
		if expiry.After(lifetimes[binding]) {
			lifetimes[binding] = expiry
		}
	}
	return lifetimes, expired, rows.Err()
}
