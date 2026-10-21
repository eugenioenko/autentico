package devicecode

import (
	"database/sql"
	"errors"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
)

func AuthorizeDeviceCode(userCode string, userID string) error {
	_, err := db.GetDB().Exec(
		`UPDATE device_codes SET status = 'authorized', user_id = ? WHERE user_code = ? AND status = 'pending'`,
		userID, userCode,
	)
	return err
}

func DenyDeviceCode(userCode string) error {
	_, err := db.GetDB().Exec(
		`UPDATE device_codes SET status = 'denied' WHERE user_code = ? AND status = 'pending'`,
		userCode,
	)
	return err
}

var ErrCodeConsumed = errors.New("device code is unavailable or already consumed")

type deviceExecer interface {
	Exec(string, ...any) (sql.Result, error)
}

func ConsumeDeviceCode(code string) error {
	return consumeDeviceCode(db.GetDB(), code)
}

// ConsumeDeviceCodeTx claims an authorized device code with its token issuance.
func ConsumeDeviceCodeTx(tx *sql.Tx, code string) error {
	return consumeDeviceCode(tx, code)
}

func consumeDeviceCode(exec deviceExecer, code string) error {
	// RFC 8628 §3.5: an authorized code can be consumed exactly once.
	result, err := exec.Exec(`UPDATE device_codes SET status = 'consumed' WHERE code = ? AND status = 'authorized'`, code)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrCodeConsumed
	}
	return nil
}

// RFC 8628 §3.5: slow_down increments the polling interval by 5 seconds
func IncrementInterval(code string) error {
	_, err := db.GetDB().Exec(
		`UPDATE device_codes SET interval_seconds = interval_seconds + 5 WHERE code = ?`,
		code,
	)
	return err
}

func UpdateLastPolledAt(code string, t time.Time) error {
	_, err := db.GetDB().Exec(
		`UPDATE device_codes SET last_polled_at = ? WHERE code = ?`,
		t, code,
	)
	return err
}
