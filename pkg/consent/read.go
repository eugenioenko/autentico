package consent

import (
	"database/sql"
	"fmt"

	"github.com/eugenioenko/autentico/pkg/db"
)

func GetConsent(userID, clientID string) (*UserConsent, error) {
	query := `SELECT id, user_id, client_id, scopes, granted_at FROM user_consents WHERE user_id = ? AND client_id = ?`
	var c UserConsent
	err := db.GetDB().QueryRow(query, userID, clientID).Scan(&c.ID, &c.UserID, &c.ClientID, &c.Scopes, &c.GrantedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get consent: %w", err)
	}
	return &c, nil
}
