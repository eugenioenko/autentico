package authcode

import (
	"database/sql"
	"errors"

	"github.com/eugenioenko/autentico/pkg/db"
)

var ErrCodeUsed = errors.New("authorization code is unavailable or already used")

type codeExecer interface {
	Exec(string, ...any) (sql.Result, error)
}

func MarkAuthCodeAsUsed(code string) error {
	return markAuthCodeAsUsed(db.GetDB(), code)
}

// MarkAuthCodeAsUsedTx claims a code in the transaction that issues its tokens.
func MarkAuthCodeAsUsedTx(tx *sql.Tx, code string) error {
	return markAuthCodeAsUsed(tx, code)
}

func markAuthCodeAsUsed(exec codeExecer, code string) error {
	// RFC 6749 §4.1.2: only one redemption may change an unused code.
	result, err := exec.Exec(`UPDATE auth_codes SET used = TRUE WHERE code = ? AND used = FALSE`, code)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrCodeUsed
	}
	return nil
}
