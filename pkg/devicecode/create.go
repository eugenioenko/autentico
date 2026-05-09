package devicecode

import "github.com/eugenioenko/autentico/pkg/db"

func CreateDeviceCode(dc DeviceCode) error {
	_, err := db.GetDB().Exec(
		`INSERT INTO device_codes (code, user_code, client_id, scope, expires_at, interval_seconds, status)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		dc.Code, dc.UserCode, dc.ClientID, dc.Scope, dc.ExpiresAt, dc.IntervalSeconds, dc.Status,
	)
	return err
}
