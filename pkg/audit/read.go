package audit

import (
	"fmt"
	"strings"

	"github.com/eugenioenko/autentico/pkg/db"
)

// ListAuditLogs returns a page of audit events matching the given filters,
// plus the total count of matching rows. Results are ordered newest-first.
func ListAuditLogs(event, actorID string, limit, offset int) ([]AuditLog, int, error) {
	var conditions []string
	var args []interface{}

	if event != "" {
		conditions = append(conditions, "event = ?")
		args = append(args, event)
	}
	if actorID != "" {
		conditions = append(conditions, "actor_id = ?")
		args = append(args, actorID)
	}

	where := ""
	if len(conditions) > 0 {
		where = " WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total matching rows
	var total int
	countQuery := "SELECT COUNT(*) FROM audit_logs" + where
	if err := db.GetDB().QueryRow(countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count audit logs: %w", err)
	}

	// Fetch the page
	query := "SELECT id, event, actor_id, actor_username, target_type, target_id, detail, ip_address, created_at FROM audit_logs" +
		where + " ORDER BY created_at DESC LIMIT ? OFFSET ?"
	pageArgs := append(args, limit, offset)

	rows, err := db.GetDB().Query(query, pageArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list audit logs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var logs []AuditLog
	for rows.Next() {
		var l AuditLog
		if err := rows.Scan(&l.ID, &l.Event, &l.ActorID, &l.ActorUsername, &l.TargetType, &l.TargetID, &l.Detail, &l.IPAddress, &l.CreatedAt); err != nil {
			return nil, 0, fmt.Errorf("failed to scan audit log: %w", err)
		}
		logs = append(logs, l)
	}
	if logs == nil {
		logs = []AuditLog{}
	}
	return logs, total, rows.Err()
}
