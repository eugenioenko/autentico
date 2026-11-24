package passkey

import (
	"database/sql"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
)

func CreatePasskeyChallenge(challenge PasskeyChallenge) error {
	query := `
		INSERT INTO passkey_challenges (id, user_id, challenge_data, type, login_state, expires_at, used)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`
	var userID *string
	if challenge.UserID != "" {
		userID = &challenge.UserID
	}
	_, err := db.GetDB().Exec(query,
		challenge.ID,
		userID,
		challenge.ChallengeData,
		challenge.Type,
		challenge.LoginState,
		challenge.ExpiresAt,
		challenge.Used,
	)
	return err
}

func CreatePasskeyCredential(cred PasskeyCredential) error { return insertCredential(db.GetDB(), cred) }
func insertCredential(writer interface {
	Exec(string, ...any) (sql.Result, error)
}, cred PasskeyCredential) error {
	query := `
		INSERT INTO passkey_credentials (id, user_id, name, credential, created_at)
		VALUES (?, ?, ?, ?, ?)
	`
	_, err := writer.Exec(query,
		cred.ID,
		cred.UserID,
		cred.Name,
		cred.Credential,
		time.Now(),
	)
	return err
}
