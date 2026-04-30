package consent

import (
	"fmt"

	"github.com/eugenioenko/autentico/pkg/db"
)

func DeleteConsent(id string) error {
	_, err := db.GetDB().Exec(`DELETE FROM user_consents WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("failed to delete consent: %w", err)
	}
	return nil
}

func DeleteConsentsByClient(clientID string) error {
	_, err := db.GetDB().Exec(`DELETE FROM user_consents WHERE client_id = ?`, clientID)
	if err != nil {
		return fmt.Errorf("failed to delete consents by client: %w", err)
	}
	return nil
}

func DeleteConsentsByUser(userID string) error {
	_, err := db.GetDB().Exec(`DELETE FROM user_consents WHERE user_id = ?`, userID)
	if err != nil {
		return fmt.Errorf("failed to delete consents by user: %w", err)
	}
	return nil
}
