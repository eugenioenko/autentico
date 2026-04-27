package trusteddevice

import (
	"github.com/eugenioenko/autentico/pkg/db"
)

func CreateTrustedDevice(device TrustedDevice) error {
	query := `
		INSERT INTO trusted_devices (id, user_id, device_name, expires_at)
		VALUES (?, ?, ?, ?)
	`
	_, err := db.GetDB().Exec(query, device.ID, device.UserID, device.DeviceName, device.ExpiresAt)
	return err
}
