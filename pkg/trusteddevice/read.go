package trusteddevice

import (
	"database/sql"
	"fmt"

	"github.com/eugenioenko/autentico/pkg/db"
)

func TrustedDevicesByUserID(userID string) ([]*TrustedDevice, error) {
	query := `
		SELECT id, user_id, device_name, created_at, last_used_at, expires_at
		FROM trusted_devices WHERE user_id = ?
	`
	rows, err := db.GetDB().Query(query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list trusted devices: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var devices []*TrustedDevice
	for rows.Next() {
		var d TrustedDevice
		if err := rows.Scan(&d.ID, &d.UserID, &d.DeviceName, &d.CreatedAt, &d.LastUsedAt, &d.ExpiresAt); err != nil {
			return nil, fmt.Errorf("failed to scan trusted device: %w", err)
		}
		devices = append(devices, &d)
	}
	return devices, rows.Err()
}

func TrustedDeviceByID(id string) (*TrustedDevice, error) {
	var d TrustedDevice
	query := `
		SELECT id, user_id, device_name, created_at, last_used_at, expires_at
		FROM trusted_devices WHERE id = ?
	`
	row := db.GetDB().QueryRow(query, id)
	err := row.Scan(&d.ID, &d.UserID, &d.DeviceName, &d.CreatedAt, &d.LastUsedAt, &d.ExpiresAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("trusted device not found")
		}
		return nil, fmt.Errorf("failed to get trusted device: %w", err)
	}
	return &d, nil
}
