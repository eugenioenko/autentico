package audit

import (
	"fmt"

	"github.com/eugenioenko/autentico/pkg/api"
	"github.com/eugenioenko/autentico/pkg/db"
)

var auditListConfig = api.ListConfig{
	AllowedSort: map[string]bool{
		"created_at": true,
		"event":      true,
	},
	SearchColumns: []string{
		"actor_username", "target_id", "ip_address", "detail",
	},
	AllowedFilters: map[string]bool{
		"event": true,
	},
	DefaultSort: "created_at",
	MaxLimit:    200,
}

func ListAuditLogsWithParams(params api.ListParams, dateWhere string, dateArgs []any) ([]AuditLog, int, error) {
	lq := api.BuildListQuery(params, auditListConfig)

	baseWhere := "WHERE 1=1"
	allArgs := append(dateArgs, lq.Args...)

	var total int
	countQuery := "SELECT COUNT(*) FROM audit_logs " + baseWhere + dateWhere + lq.Where
	if err := db.GetDB().QueryRow(countQuery, allArgs...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count audit logs: %w", err)
	}

	query := `SELECT id, event, actor_id, actor_username, target_type, target_id, detail, ip_address, created_at
		FROM audit_logs ` + baseWhere + dateWhere + lq.Where + lq.Order
	rows, err := db.GetDB().Query(query, allArgs...)
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
