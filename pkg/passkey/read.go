package passkey

import (
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/go-webauthn/webauthn/webauthn"
)

func PasskeyChallengeByID(id string) (*PasskeyChallenge, error) {
	var c PasskeyChallenge
	query := `
		SELECT id, user_id, challenge_data, type, login_state, created_at, expires_at, used
		FROM passkey_challenges WHERE id = ?
	`
	row := db.GetDB().QueryRow(query, id)
	err := row.Scan(
		&c.ID,
		&c.UserID,
		&c.ChallengeData,
		&c.Type,
		&c.LoginState,
		&c.CreatedAt,
		&c.ExpiresAt,
		&c.Used,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("passkey challenge not found")
		}
		return nil, fmt.Errorf("failed to get passkey challenge: %w", err)
	}
	return &c, nil
}

func PasskeyCredentialsByUserID(userID string) ([]PasskeyCredential, error) {
	query := `
		SELECT id, user_id, name, credential, created_at, last_used_at
		FROM passkey_credentials WHERE user_id = ?
	`
	rows, err := db.GetDB().Query(query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list passkey credentials: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var creds []PasskeyCredential
	for rows.Next() {
		var c PasskeyCredential
		if err := rows.Scan(&c.ID, &c.UserID, &c.Name, &c.Credential, &c.CreatedAt, &c.LastUsedAt); err != nil {
			return nil, fmt.Errorf("failed to scan passkey credential: %w", err)
		}
		creds = append(creds, c)
	}
	return creds, rows.Err()
}

// CredentialsToWebAuthn converts stored PasskeyCredentials to webauthn.Credential slice.
func CredentialsToWebAuthn(creds []PasskeyCredential) []webauthn.Credential {
	var result []webauthn.Credential
	for _, c := range creds {
		var cred webauthn.Credential
		if err := json.Unmarshal([]byte(c.Credential), &cred); err == nil {
			result = append(result, cred)
		}
	}
	return result
}
