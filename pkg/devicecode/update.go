package devicecode

import (
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

func ConsumeDeviceCode(code string) error {
	_, err := db.GetDB().Exec(
		`UPDATE device_codes SET status = 'consumed' WHERE code = ? AND status = 'authorized'`,
		code,
	)
	return err
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
