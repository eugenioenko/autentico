package federation

import (
	"fmt"

	"github.com/eugenioenko/autentico/pkg/db"
)

func DeleteFederationProvider(id string) error {
	_, err := db.GetDB().Exec(`DELETE FROM federation_providers WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("failed to delete federation provider: %w", err)
	}
	return nil
}
