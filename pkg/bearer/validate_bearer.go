package bearer

import (
	"fmt"
	"net/http"

	"github.com/eugenioenko/autentico/pkg/jwtutil"
	"github.com/eugenioenko/autentico/pkg/session"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// Validated is a fully-verified user-backed bearer credential: the JWT is
// signed correctly, unexpired, has the correct audience, and is tied to a
// session that has not been deactivated.
type Validated struct {
	Token   string
	Claims  *jwtutil.AccessTokenClaims
	Session *session.Session
}

// ValidateBearer parses the Authorization header and returns a fully
// verified user-backed bearer credential.
//
// It is the single entry point used by handlers that accept a user-backed
// bearer token so that each site enforces the same liveness check.
// Callers add their own authorization (role, audience, ownership) on top
// of the returned claims/session.
//
// Not applicable to client_credentials tokens (no session). Admin-API
// middleware uses its own flow because of the service-account fast path.
func ValidateBearer(r *http.Request) (*Validated, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, fmt.Errorf("missing Authorization header")
	}
	token := utils.ExtractBearerToken(authHeader)
	if token == "" {
		return nil, fmt.Errorf("invalid Authorization header")
	}
	claims, err := jwtutil.ValidateAccessToken(token)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %v", err)
	}
	sess, err := session.SessionByAccessToken(token)
	if err != nil {
		return nil, fmt.Errorf("invalid session: %v", err)
	}
	if sess.DeactivatedAt != nil {
		return nil, fmt.Errorf("session has been deactivated")
	}
	return &Validated{Token: token, Claims: claims, Session: sess}, nil
}
