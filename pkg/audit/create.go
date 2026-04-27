package audit

import (
	"encoding/json"
	"fmt"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/rs/xid"
)

// Log records an audit event synchronously. Actor can be nil when the
// acting user is unknown (e.g. failed login). Detail can be nil for
// events with no extra data. Returns immediately if audit logging is
// disabled (retention is "0" or empty).
func Log(event Event, actor Actor, targetType TargetType, targetID string, detail map[string]string, ip string) {
	retention := config.Get().AuditLogRetentionStr
	if retention == "" || retention == "0" {
		return
	}

	var actorIDParam interface{}
	var actorUsername string
	if actor != nil {
		if id := actor.GetID(); id != "" {
			actorIDParam = id
		}
		actorUsername = actor.GetUsername()
	}

	var detailStr string
	if len(detail) > 0 {
		if b, err := json.Marshal(detail); err == nil {
			detailStr = string(b)
		}
	}

	id := xid.New().String()
	_, err := db.GetDB().Exec(
		`INSERT INTO audit_logs (id, event, actor_id, actor_username, target_type, target_id, detail, ip_address)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		id, string(event), actorIDParam, actorUsername, string(targetType), targetID, detailStr, ip,
	)
	if err != nil {
		fmt.Printf("[audit] failed to log event %s: %v\n", event, err)
	}
}
