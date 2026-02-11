package session

import (
	"database/sql"
	"fmt"

	"github.com/eugenioenko/autentico/pkg/db"
)

func ListSessions() ([]*Session, error) {
	query := `
		SELECT id, user_id, user_agent, ip_address, device_id, last_activity_at, location, created_at, expires_at, deactivated_at
		FROM sessions ORDER BY created_at DESC
	`
	rows, err := db.GetDB().Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to list sessions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanSessions(rows)
}

func ListSessionsByUser(userID string) ([]*Session, error) {
	query := `
		SELECT id, user_id, user_agent, ip_address, device_id, last_activity_at, location, created_at, expires_at, deactivated_at
		FROM sessions WHERE user_id = ? ORDER BY created_at DESC
	`
	rows, err := db.GetDB().Query(query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list sessions by user: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanSessions(rows)
}

func scanSessions(rows *sql.Rows) ([]*Session, error) {
	var sessions []*Session
	for rows.Next() {
		var s Session
		if err := rows.Scan(
			&s.ID, &s.UserID, &s.UserAgent, &s.IPAddress,
			&s.DeviceID, &s.LastActivityAt, &s.Location,
			&s.CreatedAt, &s.ExpiresAt, &s.DeactivatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan session: %w", err)
		}
		sessions = append(sessions, &s)
	}
	return sessions, rows.Err()
}

func DeactivateSessionByID(sessionID string) error {
	query := `UPDATE sessions SET deactivated_at = CURRENT_TIMESTAMP WHERE id = ?`
	result, err := db.GetDB().Exec(query, sessionID)
	if err != nil {
		return fmt.Errorf("failed to deactivate session: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check affected rows: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("session not found")
	}
	return nil
}

func SessionByID(sessionID string) (*Session, error) {
	var session Session
	query := `
		SELECT id, user_id, access_token, refresh_token, user_agent, ip_address, location, created_at, expires_at, deactivated_at
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
		&session.DeactivatedAt,
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
		SELECT id, user_id, access_token, refresh_token, user_agent, ip_address, location, created_at, expires_at, deactivated_at
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
		&session.DeactivatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("session not found")
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	return &session, nil
}
