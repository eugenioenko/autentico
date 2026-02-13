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
	query := `UPDATE mfa_challenges SET code = ? WHERE id = ?`
	_, err := db.GetDB().Exec(query, code, id)
	return err
}
