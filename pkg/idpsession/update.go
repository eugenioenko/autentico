package idpsession

import (
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
)

func UpdateLastActivity(sessionID string) error {
	query := `
		UPDATE idp_sessions
		SET last_activity_at = ?
		WHERE id = ? AND deactivated_at IS NULL;
	`
	_, err := db.GetDB().Exec(query, time.Now().UTC(), sessionID)
	return err
}

func DeactivateIdpSession(sessionID string) error {
	query := `
		UPDATE idp_sessions
		SET deactivated_at = ?
		WHERE id = ? AND deactivated_at IS NULL;
	`
	_, err := db.GetDB().Exec(query, time.Now().UTC(), sessionID)
	return err
}

func DeactivateAllForUser(userID string) error {
	query := `
		UPDATE idp_sessions
		SET deactivated_at = ?
		WHERE user_id = ? AND deactivated_at IS NULL;
	`
	_, err := db.GetDB().Exec(query, time.Now().UTC(), userID)
	return err
}
