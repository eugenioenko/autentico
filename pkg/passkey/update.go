package passkey

import (
	"encoding/json"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/go-webauthn/webauthn/webauthn"
)

func MarkPasskeyChallengeUsed(id string) error {
	_, err := db.GetDB().Exec(`UPDATE passkey_challenges SET used = TRUE WHERE id = ?`, id)
	return err
}

// UpdatePasskeyCredential stores the updated credential (e.g. new sign count) and sets last_used_at.
func UpdatePasskeyCredential(credentialID string, cred webauthn.Credential) error {
	credJSON, err := json.Marshal(cred)
	if err != nil {
		return err
	}
	_, err = db.GetDB().Exec(
		`UPDATE passkey_credentials SET credential = ?, last_used_at = ? WHERE id = ?`,
		string(credJSON), time.Now(), credentialID,
	)
	return err
}
