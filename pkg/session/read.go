package session

import (
	"database/sql"
	"fmt"

	"github.com/eugenioenko/autentico/pkg/db"
)

func SessionByID(sessionID string) (*Session, error) {
	var session Session
	query := `
		SELECT id, user_id, access_token, refresh_token, user_agent, ip_address, location, created_at, expires_at
		FROM sessions WHERE id = ?
	`
	row := db.GetDB().QueryRow(query, sessionID)
	err := row.Scan(
		&session.ID,
		&session.UserID,
		&session.AccessToken,
		&session.RefreshToken,
		&session.UserAgent,
		&session.IPAddress,
		&session.Location,
		&session.CreatedAt,
		&session.ExpiresAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("session not found")
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	return &session, nil
}

func SessionByAccessToken(accessToken string) (*Session, error) {
	var session Session
	query := `
		SELECT id, user_id, access_token, refresh_token, user_agent, ip_address, location, created_at, expires_at
		FROM sessions
		WHERE access_token = ?
	`
	row := db.GetDB().QueryRow(query, accessToken)
	err := row.Scan(
		&session.ID,
		&session.UserID,
		&session.AccessToken,
		&session.RefreshToken,
		&session.UserAgent,
		&session.IPAddress,
		&session.Location,
		&session.CreatedAt,
		&session.ExpiresAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("session not found")
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	return &session, nil
}
