package session

import (
	"autentico/pkg/db"
	. "autentico/pkg/model"
)

func CreateSession(session Session) error {
	query := `
		INSERT INTO sessions (
			id, user_id, access_token, refresh_token,
			user_agent, ip_address, location, expires_at
		)VALUES (?, ?, ?, ?, ?, ?, ?, ?);
	`
	_, err := db.GetDB().Exec(query,
		session.ID,
		session.UserID,
		session.AccessToken,
		session.RefreshToken,
		session.UserAgent,
		session.IPAddress,
		session.Location,
		session.ExpiresAt,
	)

	return err
}
