package session

import (
	"github.com/eugenioenko/autentico/pkg/db"
)

func CreateSession(session Session) error {
	query := `
		INSERT INTO sessions (
			id, user_id, access_token, refresh_token,
			user_agent, ip_address, location, expires_at, idp_session_id
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
	`
	// idp_session_id nullable — left NULL for non-browser grants (ROPC,
	// client_credentials) and pre-migration rows so cascade queries skip them.
	var idpSession interface{}
	if session.IdpSessionID != nil && *session.IdpSessionID != "" {
		idpSession = *session.IdpSessionID
	}
	_, err := db.GetWriteDB().Exec(query,
		session.ID,
		session.UserID,
		session.AccessToken,
		session.RefreshToken,
		session.UserAgent,
		session.IPAddress,
		session.Location,
		session.ExpiresAt,
		idpSession,
	)

	return err
}
