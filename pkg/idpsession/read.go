package idpsession

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/eugenioenko/autentico/pkg/api"
	"github.com/eugenioenko/autentico/pkg/db"
)

var idpSessionListConfig = api.ListConfig{
	AllowedSort: map[string]bool{
		"last_activity_at": true,
		"created_at":       true,
	},
	SearchColumns:  []string{},
	AllowedFilters: map[string]bool{},
	DefaultSort:    "last_activity_at",
	MaxLimit:       api.DefaultMaxLimit,
	TableAlias:     "s",
}

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

// DeviceRow is the flat projection of an IdP session — one row per
// browser/device the user is signed in on.
type DeviceRow struct {
	ID              string
	UserID          string
	Username        string
	Email           string
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

	return scanDeviceRows(rows, false)
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

	return scanDeviceRows(rows, false)
}

func scanDeviceRows(rows *sql.Rows, withUserInfo bool) ([]DeviceRow, error) {
	var out []DeviceRow
	for rows.Next() {
		var r DeviceRow
		var userAgent, ipAddress *string
		var err error
		if withUserInfo {
			var email *string
			err = rows.Scan(&r.ID, &r.UserID, &r.Username, &email, &userAgent, &ipAddress, &r.LastActivityAt, &r.CreatedAt, &r.ActiveAppsCount)
			if email != nil {
				r.Email = *email
			}
		} else {
			err = rows.Scan(&r.ID, &r.UserID, &userAgent, &ipAddress, &r.LastActivityAt, &r.CreatedAt, &r.ActiveAppsCount)
		}
		if err != nil {
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

func ListIdpSessionsWithParams(params api.ListParams, dateWhere string, dateArgs []any) ([]DeviceRow, int, error) {
	var searchWhere string
	var searchArgs []any
	if params.Search != "" {
		pattern := "%" + params.Search + "%"
		searchWhere = " AND (u.username LIKE ? OR u.email LIKE ? OR s.ip_address LIKE ?)"
		searchArgs = []any{pattern, pattern, pattern}
	}
	params.Search = ""

	lq := api.BuildListQuery(params, idpSessionListConfig)

	baseFrom := "FROM idp_sessions s JOIN users u ON s.user_id = u.id"
	baseWhere := "WHERE s.deactivated_at IS NULL"
	allArgs := append(dateArgs, searchArgs...)
	allArgs = append(allArgs, lq.Args...)

	var total int
	countQuery := "SELECT COUNT(*) " + baseFrom + " " + baseWhere + dateWhere + searchWhere + lq.Where
	if err := db.GetDB().QueryRow(countQuery, allArgs...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count idp sessions: %w", err)
	}

	query := `SELECT s.id, s.user_id, u.username, u.email, s.user_agent, s.ip_address, s.last_activity_at, s.created_at,
		(SELECT COUNT(*) FROM sessions WHERE idp_session_id = s.id AND deactivated_at IS NULL) AS active_apps_count
		` + baseFrom + ` ` + baseWhere + dateWhere + searchWhere + lq.Where + lq.Order
	rows, err := db.GetDB().Query(query, allArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list idp sessions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	devices, err := scanDeviceRows(rows, true)
	return devices, total, err
}
