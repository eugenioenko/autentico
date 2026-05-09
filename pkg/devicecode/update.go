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

func UpdateLastPolledAt(code string, t time.Time) error {
	_, err := db.GetDB().Exec(
		`UPDATE device_codes SET last_polled_at = ? WHERE code = ?`,
		t, code,
	)
	return err
}
