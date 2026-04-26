package trusteddevice

import (
	"fmt"

	"github.com/eugenioenko/autentico/pkg/db"
)

func DeleteTrustedDevice(id string) error {
	result, err := db.GetWriteDB().Exec(`DELETE FROM trusted_devices WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("failed to delete trusted device: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to delete trusted device: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("trusted device not found")
	}
	return nil
}
