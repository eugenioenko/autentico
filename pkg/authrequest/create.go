package authrequest

import (
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/rs/xid"
)

// TTL is the lifetime of an authorize request. Requests older than this
// are considered expired and will be rejected by the login/signup handlers.
const TTL = 10 * time.Minute

// Create stores a new authorize request and returns its ID.
func Create(req AuthorizeRequest) (string, error) {
	req.ID = xid.New().String()
	req.CreatedAt = time.Now().UTC()
	req.ExpiresAt = time.Now().Add(TTL).UTC()

	_, err := db.GetDB().Exec(`
		INSERT INTO authorize_requests (id, client_id, redirect_uri, scope, state, nonce, code_challenge, code_challenge_method, response_type, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, req.ID, req.ClientID, req.RedirectURI, req.Scope, req.State, req.Nonce, req.CodeChallenge, req.CodeChallengeMethod, req.ResponseType, req.CreatedAt, req.ExpiresAt)
	if err != nil {
		return "", err
	}
	return req.ID, nil
}
