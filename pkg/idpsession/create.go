package idpsession

import (
	"github.com/eugenioenko/autentico/pkg/db"
)

func CreateIdpSession(session IdpSession) error {
	query := `
		INSERT INTO idp_sessions (
			id, user_id, user_agent, ip_address
		) VALUES (?, ?, ?, ?);
	`
	_, err := db.GetDB().Exec(query,
		session.ID,
		session.UserID,
		session.UserAgent,
		session.IPAddress,
	)

	return err
}
