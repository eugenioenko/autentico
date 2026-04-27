package mfa

import (
	"github.com/eugenioenko/autentico/pkg/db"
)

func CreateMfaChallenge(challenge MfaChallenge) error {
	query := `
		INSERT INTO mfa_challenges (id, user_id, method, code, login_state, expires_at, used)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`
	_, err := db.GetDB().Exec(query,
		challenge.ID,
		challenge.UserID,
		challenge.Method,
		challenge.Code,
		challenge.LoginState,
		challenge.ExpiresAt,
		challenge.Used,
	)
	return err
}
