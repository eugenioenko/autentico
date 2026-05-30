package magiclink

import (
	"crypto/rand"
	"encoding/base64"
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

func getMagicLinkTokenByCodeHash(userID, codeHash string) (tokenHash string, expiresAt time.Time, usedAt *time.Time, err error) {
	err = db.GetDB().QueryRow(
		`SELECT token_hash, expires_at, used_at FROM magic_link_tokens WHERE user_id = ? AND code_hash = ? ORDER BY created_at DESC LIMIT 1`,
		userID, codeHash,
	).Scan(&tokenHash, &expiresAt, &usedAt)
	return
}

func markTokenUsed(tokenHash string) {
	if _, err := db.GetDB().Exec(
		`UPDATE magic_link_tokens SET used_at = CURRENT_TIMESTAMP WHERE token_hash = ?`,
		tokenHash,
	); err != nil {
		slog.Error("magiclink: failed to mark token as used", "error", err)
	}
}

func invalidatePreviousTokens(userID string) {
	if _, err := db.GetDB().Exec(
		`UPDATE magic_link_tokens SET used_at = CURRENT_TIMESTAMP WHERE user_id = ? AND used_at IS NULL`,
		userID,
	); err != nil {
		slog.Error("magiclink: failed to invalidate previous tokens", "error", err, "user_id", userID)
	}
}
