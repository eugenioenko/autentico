package passwordreset

import (
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/utils"
	"github.com/rs/xid"
)

// generateToken returns a URL-safe random token and its SHA-256 hash.
func generateToken() (rawToken, tokenHash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return
	}
	rawToken = base64.RawURLEncoding.EncodeToString(b)
	tokenHash = utils.HashSHA256(rawToken)
	return
}

// createResetToken stores a new password reset token in the database.
func createResetToken(userID, tokenHash string, expiresAt time.Time) error {
	id := xid.New().String()
	_, err := db.GetDB().Exec(
		`INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)`,
		id, userID, tokenHash, expiresAt,
	)
	return err
}

// getResetTokenInfo returns the user ID, expiry, and used timestamp for a token hash.
func getResetTokenInfo(tokenHash string) (userID string, expiresAt time.Time, usedAt *time.Time, err error) {
	err = db.GetDB().QueryRow(
		`SELECT user_id, expires_at, used_at FROM password_reset_tokens WHERE token_hash = ?`,
		tokenHash,
	).Scan(&userID, &expiresAt, &usedAt)
	return
}

// markTokenUsed sets the used_at timestamp on a token.
func markTokenUsed(tokenHash string) {
	_, _ = db.GetDB().Exec(
		`UPDATE password_reset_tokens SET used_at = CURRENT_TIMESTAMP WHERE token_hash = ?`,
		tokenHash,
	)
}

// invalidatePreviousTokens marks all unused tokens for a user as used,
// so only the latest reset link is valid.
func invalidatePreviousTokens(userID string) {
	_, _ = db.GetDB().Exec(
		`UPDATE password_reset_tokens SET used_at = CURRENT_TIMESTAMP WHERE user_id = ? AND used_at IS NULL`,
		userID,
	)
}

// deactivateUserSessions deactivates all active sessions for a user.
func deactivateUserSessions(userID string) {
	_, _ = db.GetDB().Exec(
		`UPDATE sessions SET deactivated_at = CURRENT_TIMESTAMP WHERE user_id = ? AND deactivated_at IS NULL`,
		userID,
	)
}
