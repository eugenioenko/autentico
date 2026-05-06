package consent

import (
	"fmt"

	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/db"
)

func UpsertConsent(userID, clientID, scopes string) error {
	id, err := authcode.GenerateSecureCode()
	if err != nil {
		return fmt.Errorf("failed to generate consent id: %w", err)
	}

	query := `
		INSERT INTO user_consents (id, user_id, client_id, scopes, granted_at)
		VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(user_id, client_id) DO UPDATE SET
			scopes = excluded.scopes,
			granted_at = CURRENT_TIMESTAMP
	`
	_, err = db.GetDB().Exec(query, id, userID, clientID, scopes)
	if err != nil {
		return fmt.Errorf("failed to upsert consent: %w", err)
	}
	return nil
}
