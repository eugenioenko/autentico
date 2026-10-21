package magiclink

import (
	"context"
	"crypto/rand"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/utils"
	"github.com/rs/xid"
)

func generateToken() (rawToken, tokenHash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return
	}
	rawToken = base64.RawURLEncoding.EncodeToString(b)
	tokenHash = utils.HashSHA256(rawToken)
	return
}

func generateCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

func createMagicLinkToken(userID, tokenHash, codeHash string, expiresAt time.Time) error {
	id := xid.New().String()
	_, err := db.GetDB().Exec(
		`INSERT INTO magic_link_tokens (id, user_id, token_hash, code_hash, expires_at) VALUES (?, ?, ?, ?, ?)`,
		id, userID, tokenHash, codeHash, expiresAt,
	)
	return err
}

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

func invalidatePreviousTokens(userID string) {
	if _, err := db.GetDB().Exec(
		`UPDATE magic_link_tokens SET used_at = CURRENT_TIMESTAMP WHERE user_id = ? AND used_at IS NULL`,
		userID,
	); err != nil {
		slog.Error("magiclink: failed to invalidate previous tokens", "error", err, "user_id", userID)
	}
}
