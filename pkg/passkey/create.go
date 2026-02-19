package passkey

import (
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
)

func CreatePasskeyChallenge(challenge PasskeyChallenge) error {
	query := `
		INSERT INTO passkey_challenges (id, user_id, challenge_data, type, login_state, expires_at, used)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`
	_, err := db.GetDB().Exec(query,
		challenge.ID,
		challenge.UserID,
		challenge.ChallengeData,
		challenge.Type,
		challenge.LoginState,
		challenge.ExpiresAt,
		challenge.Used,
	)
	return err
}

func CreatePasskeyCredential(cred PasskeyCredential) error {
	query := `
		INSERT INTO passkey_credentials (id, user_id, name, credential, created_at)
		VALUES (?, ?, ?, ?, ?)
	`
	_, err := db.GetDB().Exec(query,
		cred.ID,
		cred.UserID,
		cred.Name,
		cred.Credential,
		time.Now(),
	)
	return err
}
