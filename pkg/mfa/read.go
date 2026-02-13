package mfa

import (
	"database/sql"
	"fmt"

	"github.com/eugenioenko/autentico/pkg/db"
)

func MfaChallengeByID(id string) (*MfaChallenge, error) {
	var challenge MfaChallenge
	query := `
		SELECT id, user_id, method, code, login_state, created_at, expires_at, used
		FROM mfa_challenges WHERE id = ?
	`
	row := db.GetDB().QueryRow(query, id)
	err := row.Scan(
		&challenge.ID,
		&challenge.UserID,
		&challenge.Method,
		&challenge.Code,
		&challenge.LoginState,
		&challenge.CreatedAt,
		&challenge.ExpiresAt,
		&challenge.Used,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("MFA challenge not found")
		}
		return nil, fmt.Errorf("failed to get MFA challenge: %w", err)
	}
	return &challenge, nil
}
