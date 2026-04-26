package authcode

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
)

func AuthCodeByCode(code string) (*AuthCode, error) {
	query := `
        SELECT code, user_id, client_id, redirect_uri, scope, nonce,
               code_challenge, code_challenge_method,
               expires_at, used, created_at, idp_session_id
        FROM auth_codes
        WHERE code = ? AND used = 0 AND expires_at > ?;
    `
	var authCode AuthCode
	var clientID, idpSessionID sql.NullString
	err := db.GetReadDB().QueryRow(query, code, time.Now().UTC()).Scan(
		&authCode.Code,
		&authCode.UserID,
		&clientID,
		&authCode.RedirectURI,
		&authCode.Scope,
		&authCode.Nonce,
		&authCode.CodeChallenge,
		&authCode.CodeChallengeMethod,
		&authCode.ExpiresAt,
		&authCode.Used,
		&authCode.CreatedAt,
		&idpSessionID,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("authorization code not found")
		}
		return nil, err // Other errors
	}

	if clientID.Valid {
		authCode.ClientID = clientID.String
	}
	if idpSessionID.Valid {
		authCode.IdpSessionID = idpSessionID.String
	}

	return &authCode, nil
}

// AuthCodeByCodeIncludingUsed returns the auth code regardless of used/expired status.
// Required by the token exchange flow for replay detection (RFC 6749 §10.6).
func AuthCodeByCodeIncludingUsed(code string) (*AuthCode, error) {
	query := `
        SELECT code, user_id, client_id, redirect_uri, scope, nonce,
               code_challenge, code_challenge_method,
               expires_at, used, created_at, idp_session_id
        FROM auth_codes
        WHERE code = ?;
    `
	var authCode AuthCode
	var clientID, idpSessionID sql.NullString
	err := db.GetReadDB().QueryRow(query, code).Scan(
		&authCode.Code,
		&authCode.UserID,
		&clientID,
		&authCode.RedirectURI,
		&authCode.Scope,
		&authCode.Nonce,
		&authCode.CodeChallenge,
		&authCode.CodeChallengeMethod,
		&authCode.ExpiresAt,
		&authCode.Used,
		&authCode.CreatedAt,
		&idpSessionID,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("authorization code not found")
		}
		return nil, err
	}

	if clientID.Valid {
		authCode.ClientID = clientID.String
	}
	if idpSessionID.Valid {
		authCode.IdpSessionID = idpSessionID.String
	}

	return &authCode, nil
}
