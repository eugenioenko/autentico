package idpsession

import (
	"github.com/eugenioenko/autentico/pkg/db"
)

func UpdateLastActivity(sessionID string) error {
	query := `
		UPDATE idp_sessions
		SET last_activity_at = CURRENT_TIMESTAMP
		WHERE id = ? AND deactivated_at IS NULL;
	`
	_, err := db.GetDB().Exec(query, sessionID)
	return err
}

func DeactivateIdpSession(sessionID string) error {
	query := `
		UPDATE idp_sessions
		SET deactivated_at = CURRENT_TIMESTAMP
		WHERE id = ? AND deactivated_at IS NULL;
	`
	_, err := db.GetDB().Exec(query, sessionID)
	return err
}
