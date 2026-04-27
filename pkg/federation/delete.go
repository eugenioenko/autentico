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

func DeleteFederatedIdentity(id string) error {
	result, err := db.GetDB().Exec(`DELETE FROM federated_identities WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("failed to delete federated identity: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to delete federated identity: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("federated identity not found")
	}
	return nil
}
