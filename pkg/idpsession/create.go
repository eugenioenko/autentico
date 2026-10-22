package idpsession

import (
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
)

// CreateIdpSession persists browser metadata and evidence supplied by completed authentication.
func CreateIdpSession(session IdpSession) error {
	now := time.Now().UTC()
	query := `
		INSERT INTO idp_sessions (
			id, user_id, user_agent, ip_address, last_activity_at, created_at, mfa_method
		) VALUES (?, ?, ?, ?, ?, ?, ?);
	`
	_, err := db.GetDB().Exec(query,
		session.ID,
		session.UserID,
		session.UserAgent,
		session.IPAddress,
		now,
		now,
		session.MfaMethod,
	)

	return err
}
