package magiclink

import (
	"context"
	"crypto/rand"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/utils"
	"github.com/rs/xid"
)

// generateToken creates a random 256-bit link credential and its storage hash.
func generateToken() (rawToken, tokenHash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return
	}
	rawToken = base64.RawURLEncoding.EncodeToString(b)
	tokenHash = utils.HashSHA256(rawToken)
	return
}

// generateCode selects a six-digit code uniformly using crypto/rand.
func generateCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// errIssuanceSuppressed keeps cooldown and exhausted-budget outcomes indistinguishable.
var errIssuanceSuppressed = errors.New("magic link issuance suppressed")

const magicLinkRequestCooldown = time.Minute

// issueMagicLinkToken replaces a challenge without extending its account-level guessing window.
func issueMagicLinkToken(userID, tokenHash, codeHash string, requestedExpiry time.Time) (time.Time, error) {
	var expiry time.Time
	err := magicLinkWrite(func(tx *sql.Tx) error {
		// OWASP Authentication §Login Throttling / §Account Lockout: serialize
		// requests before reading the shared user budget, including across processes.
		result, err := tx.Exec(`UPDATE users SET id=id WHERE id=? AND deactivated_at IS NULL`, userID)
		if err != nil {
			return err
		}
		count, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if count != 1 {
			return errIssuanceSuppressed
		}
		now := time.Now().UTC()
		if !now.Before(requestedExpiry) {
			return fmt.Errorf("magic link expiry must be in the future")
		}
		var previousExpiry, created time.Time
		var attempts int
		err = tx.QueryRow(`SELECT expires_at,created_at,failed_attempts FROM magic_link_tokens
			WHERE user_id=? ORDER BY created_at DESC,id DESC LIMIT 1`, userID).Scan(&previousExpiry, &created, &attempts)
		expiry = requestedExpiry.UTC()
		switch {
		case errors.Is(err, sql.ErrNoRows):
			attempts = 0
		case err != nil:
			return err
		default:
			if now.Sub(created) < magicLinkRequestCooldown {
				return errIssuanceSuppressed
			}
			if now.Before(previousExpiry) {
				// Used/exhausted rows retain the budget. Requesting a replacement cannot
				// clear failures or prolong the original window; expiry starts a new one.
				if attempts >= maxCodeAttempts {
					return errIssuanceSuppressed
				}
				if previousExpiry.Before(expiry) {
					expiry = previousExpiry.UTC()
				}
			} else {
				attempts = 0
			}
		}
		if _, err = tx.Exec(`UPDATE magic_link_tokens SET used_at=? WHERE user_id=? AND used_at IS NULL`, now, userID); err != nil {
			return err
		}
		_, err = tx.Exec(`INSERT INTO magic_link_tokens(id,user_id,token_hash,code_hash,expires_at,created_at,failed_attempts)
			VALUES(?,?,?,?,?,?,?)`, xid.New().String(), userID, tokenHash, codeHash, expiry, now, attempts)
		return err
	})
	if err != nil {
		return time.Time{}, err
	}
	return expiry, nil
}

// getMagicLinkTokenInfo reads expiry and consumption state for either redemption path.
func getMagicLinkTokenInfo(tokenHash string) (userID string, expiresAt time.Time, usedAt *time.Time, err error) {
	err = db.GetDB().QueryRow(
		`SELECT user_id, expires_at, used_at FROM magic_link_tokens WHERE token_hash = ?`,
		tokenHash,
	).Scan(&userID, &expiresAt, &usedAt)
	return
}

const maxCodeAttempts = 5

// getLatestUnusedMagicLinkToken identifies the challenge even when its code is wrong.
func getLatestUnusedMagicLinkToken(userID string) (tokenHash, codeHash string, expiresAt time.Time, failedAttempts int, err error) {
	err = db.GetDB().QueryRow(
		`SELECT token_hash, code_hash, expires_at, failed_attempts FROM magic_link_tokens
		 WHERE user_id = ? AND used_at IS NULL ORDER BY created_at DESC, id DESC LIMIT 1`,
		userID,
	).Scan(&tokenHash, &codeHash, &expiresAt, &failedAttempts)
	return
}

// recordFailedCodeAttempt atomically exhausts both credentials on the fifth failure.
// Exhausted or concurrently consumed challenges return sql.ErrNoRows.
func recordFailedCodeAttempt(tokenHash string) (int, error) {
	var attempts int
	err := db.GetWriteDB().QueryRow(
		`UPDATE magic_link_tokens
		 SET failed_attempts = failed_attempts + 1,
		     used_at = CASE WHEN failed_attempts + 1 >= ? THEN CURRENT_TIMESTAMP ELSE used_at END
		 WHERE token_hash = ? AND used_at IS NULL AND failed_attempts < ?
		 RETURNING failed_attempts`,
		maxCodeAttempts, tokenHash, maxCodeAttempts,
	).Scan(&attempts)
	return attempts, err
}

// consumeMagicLinkToken claims one eligible challenge for either redemption path.
// Expiry is checked as a Go time inside the transaction because existing SQLite
// timestamps can contain different offsets and aren't lexically comparable.
// Ineligible challenges return sql.ErrNoRows; write/commit failures abort login.
func consumeMagicLinkToken(tokenHash string) error {
	return magicLinkWrite(func(tx *sql.Tx) error {
		// token_hash is unique, so RETURNING yields exactly one claimed row or none.
		var expiresAt time.Time
		if err := tx.QueryRow(
			`UPDATE magic_link_tokens SET used_at = CURRENT_TIMESTAMP
		 WHERE token_hash = ? AND used_at IS NULL AND failed_attempts < ?
		 RETURNING expires_at`, tokenHash, maxCodeAttempts,
		).Scan(&expiresAt); err != nil {
			return err
		}
		if !time.Now().Before(expiresAt) {
			return sql.ErrNoRows
		}
		return nil
	})
}

// magicLinkWrite restores or discards the reserved connection after a failed commit.
func magicLinkWrite(change func(*sql.Tx) error) error {
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
	if err := change(tx); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		// SQLite may leave the transaction open after database/sql marks it done.
		if _, rollbackErr := conn.ExecContext(ctx, "ROLLBACK"); rollbackErr != nil {
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
			err = errors.Join(err, rollbackErr)
		}
		return err
	}
	return nil
}
