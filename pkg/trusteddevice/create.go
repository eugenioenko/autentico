package trusteddevice

import (
	"fmt"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// CreateTrustedDevice persists metadata and only a hash of the cookie token.
func CreateTrustedDevice(device TrustedDevice, token string) error {
	// OWASP Session Management: identifiers exposed by APIs are not credentials.
	if device.ID == "" || token == "" || device.ID == token {
		return fmt.Errorf("trusted device requires a separate nonempty ID and cookie token")
	}
	query := `
		INSERT INTO trusted_devices (id, user_id, device_name, expires_at, token_hash)
		VALUES (?, ?, ?, ?, ?)
	`
	_, err := db.GetDB().Exec(query, device.ID, device.UserID, device.DeviceName, device.ExpiresAt, utils.HashToken(token))
	return err
}
