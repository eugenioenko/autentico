package mfa

import (
	"github.com/eugenioenko/autentico/pkg/db"
)

func MarkChallengeUsed(id string) error {
	query := `UPDATE mfa_challenges SET used = TRUE WHERE id = ?`
	_, err := db.GetDB().Exec(query, id)
	return err
}

func UpdateChallengeCode(id, code string) error {
	query := `UPDATE mfa_challenges SET code = ?, otp_sent_at = CURRENT_TIMESTAMP WHERE id = ?`
	_, err := db.GetDB().Exec(query, code, id)
	return err
}

func IncrementFailedAttempts(id string) error {
	query := `UPDATE mfa_challenges SET failed_attempts = failed_attempts + 1 WHERE id = ?`
	_, err := db.GetDB().Exec(query, id)
	return err
}
