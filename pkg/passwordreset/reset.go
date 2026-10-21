package passwordreset

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	"golang.org/x/crypto/bcrypt"
)

var errResetUnavailable = errors.New("password reset token is unavailable")

// resetPassword commits token consumption, password replacement and session
// invalidation together. Hashing happens before reserving the writer connection.
func resetPassword(ctx context.Context, tokenHash, password string) error {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
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
	var userID string
	var expiresAt time.Time
	// OWASP Forgot Password §General Security Practices: a reset credential
	// is single-use. RETURNING proves that exactly one unused token was claimed.
	err = tx.QueryRow(`UPDATE password_reset_tokens SET used_at = CURRENT_TIMESTAMP
		WHERE token_hash = ? AND used_at IS NULL RETURNING user_id, expires_at`, tokenHash).Scan(&userID, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return errResetUnavailable
	}
	if err != nil {
		return err
	}
	// Check expiry inside the transaction after waiting for the writer. Go
	// parses both historical SQLite and driver-formatted timestamps correctly.
	if !time.Now().Before(expiresAt) {
		return errResetUnavailable
	}
	result, err := tx.Exec(`UPDATE users SET password = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ? AND deactivated_at IS NULL`, string(hashed), userID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errResetUnavailable
	}
	// OWASP Forgot Password §User Resets Password: retain automatic session
	// invalidation, and never report success after a failed revocation write.
	for _, table := range []string{"sessions", "idp_sessions"} {
		if _, err := tx.Exec("UPDATE "+table+" SET deactivated_at = CURRENT_TIMESTAMP WHERE user_id = ? AND deactivated_at IS NULL", userID); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		// SQLite can leave a transaction open after a deferred COMMIT failure,
		// although database/sql considers the Tx finished. Clean the connection.
		if _, rollbackErr := conn.ExecContext(context.Background(), "ROLLBACK"); rollbackErr != nil {
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
			err = errors.Join(err, rollbackErr)
		}
		return err
	}
	return nil
}
