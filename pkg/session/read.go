package session

import (
	"database/sql"
	"fmt"

	"github.com/eugenioenko/autentico/pkg/api"
	"github.com/eugenioenko/autentico/pkg/db"
)

var oauthSessionListConfig = api.ListConfig{
	AllowedSort: map[string]bool{
		"created_at": true,
		"expires_at": true,
	},
	SearchColumns:  []string{},
	AllowedFilters: map[string]bool{},
	DefaultSort:    "created_at",
	MaxLimit:       api.DefaultMaxLimit,
	TableAlias:     "sessions",
}

func ListSessions() ([]*Session, error) {
	query := `
		SELECT id, user_id, user_agent, ip_address, device_id, last_activity_at, location, created_at, expires_at, deactivated_at, idp_session_id
		FROM sessions ORDER BY created_at DESC
	`
	rows, err := db.GetReadDB().Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to list sessions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanSessions(rows)
}

func ListSessionsByUser(userID string) ([]*Session, error) {
	query := `
		SELECT id, user_id, user_agent, ip_address, device_id, last_activity_at, location, created_at, expires_at, deactivated_at, idp_session_id
		FROM sessions WHERE user_id = ? ORDER BY created_at DESC
	`
	rows, err := db.GetReadDB().Query(query, userID)
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
			&s.CreatedAt, &s.ExpiresAt, &s.DeactivatedAt, &s.IdpSessionID,
		); err != nil {
			return nil, fmt.Errorf("failed to scan session: %w", err)
		}
		sessions = append(sessions, &s)
	}
	return sessions, rows.Err()
}

func ListOAuthSessionsByIdpSession(idpSessionID string, params api.ListParams) ([]*Session, int, error) {
	lq := api.BuildListQuery(params, oauthSessionListConfig)

	baseWhere := "WHERE sessions.idp_session_id = ?"
	baseArgs := []any{idpSessionID}
	allArgs := append(baseArgs, lq.Args...)

	var total int
	countQuery := "SELECT COUNT(*) FROM sessions " + baseWhere + lq.Where
	if err := db.GetReadDB().QueryRow(countQuery, allArgs...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count sessions: %w", err)
	}

	query := `SELECT id, user_id, user_agent, ip_address, device_id, last_activity_at, location, created_at, expires_at, deactivated_at, idp_session_id
		FROM sessions ` + baseWhere + lq.Where + lq.Order
	rows, err := db.GetReadDB().Query(query, allArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list sessions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	sessions, err := scanSessions(rows)
	return sessions, total, err
}

func DeactivateSessionByID(sessionID string) error {
	query := `UPDATE sessions SET deactivated_at = CURRENT_TIMESTAMP WHERE id = ?`
	result, err := db.GetWriteDB().Exec(query, sessionID)
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

// SessionByIDIncludingDeactivated returns the session regardless of deactivation status.
// Callers must check DeactivatedAt to provide distinct error messages to the user.
func SessionByIDIncludingDeactivated(sessionID string) (*Session, error) {
	var session Session
	query := `
		SELECT id, user_id, access_token, refresh_token, user_agent, ip_address, location, created_at, expires_at, deactivated_at, idp_session_id
		FROM sessions WHERE id = ?
	`
	row := db.GetReadDB().QueryRow(query, sessionID)
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
		&session.IdpSessionID,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("session not found")
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	return &session, nil
}

// SessionByAccessToken returns the active session matching the access token.
// Deactivated sessions are filtered at the read layer so callers can't
// accidentally honor a revoked session.
func SessionByAccessToken(accessToken string) (*Session, error) {
	var session Session
	row := db.GetReadDB().QueryRow(`
		SELECT id, user_id, access_token, refresh_token, user_agent, ip_address, location, created_at, expires_at, deactivated_at, idp_session_id
		FROM sessions
		WHERE access_token = ? AND deactivated_at IS NULL
	`, accessToken)
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
		&session.IdpSessionID,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("session not found")
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	return &session, nil
}
