package cleanup

import (
	"log/slog"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
)

// cleanMagicLinkTokens preserves guessing budgets until their actual expiry instant.
func cleanMagicLinkTokens(threshold time.Time) error {
	// A used row can hold an exhausted account budget. Compare parsed instants:
	// lexical SQL comparisons can delete a live budget stored in another offset.
	rows, err := db.GetDB().Query(`SELECT id,expires_at FROM magic_link_tokens`)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	var expired []string
	for rows.Next() {
		var id string
		var expiry time.Time
		if err := rows.Scan(&id, &expiry); err != nil {
			return err
		}
		if expiry.Before(threshold) {
			expired = append(expired, id)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	// Expiries are immutable once issued. Close the reader before deleting;
	// replacements have unique IDs and cannot turn an expired row live again.
	for _, id := range expired {
		if _, err := db.GetDB().Exec(`DELETE FROM magic_link_tokens WHERE id=?`, id); err != nil {
			return err
		}
	}
	if len(expired) > 0 {
		slog.Info("cleanup: deleted expired rows", "table", "magic_link_tokens", "count", len(expired))
	}
	return nil
}
