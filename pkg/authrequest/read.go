package authrequest

import (
	"fmt"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
)

// GetByID retrieves an authorize request by ID. Returns an error if the
// request does not exist or has expired.
func GetByID(id string) (*AuthorizeRequest, error) {
	var req AuthorizeRequest
	err := db.GetDB().QueryRow(`
		SELECT id, client_id, redirect_uri, scope, state, nonce, code_challenge, code_challenge_method, response_type, created_at, expires_at
		FROM authorize_requests WHERE id = ?
	`, id).Scan(&req.ID, &req.ClientID, &req.RedirectURI, &req.Scope, &req.State, &req.Nonce, &req.CodeChallenge, &req.CodeChallengeMethod, &req.ResponseType, &req.CreatedAt, &req.ExpiresAt)
	if err != nil {
		return nil, err
	}
	if time.Now().After(req.ExpiresAt) {
		return nil, fmt.Errorf("authorize request has expired")
	}
	return &req, nil
}
