package idpsession

import (
	"database/sql"
	"fmt"
	"time"

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

// DeviceRow is the flat projection of an IdP session used by the account-ui
// Devices list — one row per browser/device the user is signed in on.
type DeviceRow struct {
	ID              string
	UserID          string
	UserAgent       string
	IPAddress       string
	LastActivityAt  time.Time
	CreatedAt       time.Time
	ActiveAppsCount int
}

// ListActiveDevicesForUser returns every non-deactivated IdP session for userID
// that has been active since idleCutoff (zero-value = no cutoff), with the
// count of non-deactivated OAuth sessions born from each. Ordered by most
// recent activity first.
func ListActiveDevicesForUser(userID string, idleCutoff time.Time) ([]DeviceRow, error) {
	rows, err := db.GetDB().Query(`
		SELECT s.id, s.user_id, s.user_agent, s.ip_address, s.last_activity_at, s.created_at,
		       (SELECT COUNT(*) FROM sessions
		          WHERE idp_session_id = s.id AND deactivated_at IS NULL) AS active_apps_count
		  FROM idp_sessions s
		 WHERE s.user_id = ?
		   AND s.deactivated_at IS NULL
		   AND (? = '' OR s.last_activity_at > ?)
		 ORDER BY s.last_activity_at DESC`,
		userID, idleCutoff, idleCutoff,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list idp sessions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	return scanDeviceRows(rows)
}

// ListActiveDevices returns every non-deactivated IdP session, optionally
// filtered by userID (empty = all users). Ordered by most recent activity first.
func ListActiveDevices(userID string) ([]DeviceRow, error) {
	var query string
	var args []any

	if userID != "" {
		query = `
			SELECT s.id, s.user_id, s.user_agent, s.ip_address, s.last_activity_at, s.created_at,
			       (SELECT COUNT(*) FROM sessions
			          WHERE idp_session_id = s.id AND deactivated_at IS NULL) AS active_apps_count
			  FROM idp_sessions s
			 WHERE s.user_id = ?
			   AND s.deactivated_at IS NULL
			 ORDER BY s.last_activity_at DESC`
		args = []any{userID}
	} else {
		query = `
			SELECT s.id, s.user_id, s.user_agent, s.ip_address, s.last_activity_at, s.created_at,
			       (SELECT COUNT(*) FROM sessions
			          WHERE idp_session_id = s.id AND deactivated_at IS NULL) AS active_apps_count
			  FROM idp_sessions s
			 WHERE s.deactivated_at IS NULL
			 ORDER BY s.last_activity_at DESC`
	}

	rows, err := db.GetDB().Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list idp sessions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	return scanDeviceRows(rows)
}

func scanDeviceRows(rows *sql.Rows) ([]DeviceRow, error) {
	var out []DeviceRow
	for rows.Next() {
		var r DeviceRow
		var userAgent, ipAddress *string
		if err := rows.Scan(&r.ID, &r.UserID, &userAgent, &ipAddress, &r.LastActivityAt, &r.CreatedAt, &r.ActiveAppsCount); err != nil {
			return nil, fmt.Errorf("failed to scan idp session row: %w", err)
		}
		if userAgent != nil {
			r.UserAgent = *userAgent
		}
		if ipAddress != nil {
			r.IPAddress = *ipAddress
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
