package mfa

import (
	"fmt"

	"github.com/eugenioenko/autentico/pkg/db"
)

// MarkChallengeUsed atomically consumes an MFA challenge. A challenge that has
// already been consumed is treated as an error so concurrent MFA submissions
// cannot both complete the same authorization flow.
func MarkChallengeUsed(id string) error {
	query := `UPDATE mfa_challenges SET used = TRUE WHERE id = ? AND used = FALSE`
	result, err := db.GetDB().Exec(query, id)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return fmt.Errorf("mfa challenge %q is already used or does not exist", id)
	}
	return nil
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
