package session

import (
	"database/sql"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/utils"
)

type sessionExecer interface {
	Exec(string, ...any) (sql.Result, error)
}

func CreateSession(session Session) error {
	return createSession(db.GetDB(), session)
}

// CreateSessionTx persists the session in its token issuance transaction.
func CreateSessionTx(tx *sql.Tx, session Session) error {
	return createSession(tx, session)
}

func createSession(exec sessionExecer, session Session) error {
	query := `
		INSERT INTO sessions (
			id, user_id, access_token_hash, refresh_token_hash,
			user_agent, ip_address, location, expires_at, idp_session_id
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
	`
	// idp_session_id nullable — left NULL for non-browser grants (ROPC,
	// client_credentials) and pre-migration rows so cascade queries skip them.
	var idpSession interface{}
	if session.IdpSessionID != nil && *session.IdpSessionID != "" {
		idpSession = *session.IdpSessionID
	}
	_, err := exec.Exec(query,
		session.ID,
		session.UserID,
		utils.HashToken(session.AccessToken),
		utils.HashToken(session.RefreshToken),
		session.UserAgent,
		session.IPAddress,
		session.Location,
		session.ExpiresAt,
		idpSession,
	)

	return err
}
