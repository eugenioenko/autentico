package idpsession

import (
	"database/sql"
	"fmt"

	"github.com/eugenioenko/autentico/pkg/db"
)

func IdpSessionByID(sessionID string) (*IdpSession, error) {
	var session IdpSession
	query := `
		SELECT id, user_id, user_agent, ip_address, last_activity_at, created_at
		FROM idp_sessions
		WHERE id = ? AND deactivated_at IS NULL
	`
	row := db.GetDB().QueryRow(query, sessionID)
	err := row.Scan(
		&session.ID,
		&session.UserID,
		&session.UserAgent,
		&session.IPAddress,
		&session.LastActivityAt,
		&session.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("idp session not found")
		}
		return nil, fmt.Errorf("failed to get idp session: %w", err)
	}

	return &session, nil
}
