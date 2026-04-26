package idpsession

import (
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
)

func CreateIdpSession(session IdpSession) error {
	now := time.Now().UTC()
	query := `
		INSERT INTO idp_sessions (
			id, user_id, user_agent, ip_address, last_activity_at, created_at
		) VALUES (?, ?, ?, ?, ?, ?);
	`
	_, err := db.GetWriteDB().Exec(query,
		session.ID,
		session.UserID,
		session.UserAgent,
		session.IPAddress,
		now,
		now,
	)

	return err
}
