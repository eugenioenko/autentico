package mfa

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
)

var ErrChallengeUnavailable = errors.New("MFA challenge is unavailable or already used")

func MarkChallengeUsed(id string) error {
	// RFC 6238 §5.2: retirement and method switching cannot reuse a challenge.
	result, err := db.GetDB().Exec(`UPDATE mfa_challenges SET used = TRUE WHERE id = ? AND used = FALSE`, id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrChallengeUnavailable
	}
	return nil
}

// ConsumeMfaChallenge claims the exact challenge that was verified. The
// conditional update rejects resends, method switches, exhausted and reused
// challenges; expiry is checked under the writer lock before committing.
func ConsumeMfaChallenge(ctx context.Context, challenge MfaChallenge) error {
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
	var expiresAt time.Time
	// RFC 6238 §5.2 / RFC 4226 §7.3: successful verification must claim one
	// unused, unexhausted challenge with the same user, code and login binding.
	err = tx.QueryRow(`UPDATE mfa_challenges SET used = TRUE
		WHERE id = ? AND used = FALSE AND failed_attempts < 5
		AND user_id = ? AND method = ? AND code = ? AND login_state = ?
		RETURNING expires_at`, challenge.ID, challenge.UserID, challenge.Method, challenge.Code, challenge.LoginState).Scan(&expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrChallengeUnavailable
	}
	if err != nil {
		return err
	}
	if !time.Now().Before(expiresAt) {
		return ErrChallengeUnavailable
	}
	if err := tx.Commit(); err != nil {
		// database/sql closes the Tx on COMMIT failure; SQLite may still
		// require an explicit rollback before this connection can be reused.
		if _, rollbackErr := conn.ExecContext(context.Background(), "ROLLBACK"); rollbackErr != nil {
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
			err = errors.Join(err, rollbackErr)
		}
		return err
	}
	return nil
}

func UpdateChallengeCode(id, code string) error {
	query := `UPDATE mfa_challenges SET code = ?, otp_sent_at = CURRENT_TIMESTAMP WHERE id = ?`
	_, err := db.GetDB().Exec(query, code, id)
	return err
}

func IncrementFailedAttempts(id string) error {
	query := `UPDATE mfa_challenges SET failed_attempts = failed_attempts + 1 WHERE id = ?`
	_, err := db.GetDB().Exec(query, id)
	return err
}
