package bearer

import (
	"database/sql"
	"fmt"
	"net/http"

	"github.com/eugenioenko/autentico/pkg/jwtutil"
	"github.com/eugenioenko/autentico/pkg/session"
	"github.com/eugenioenko/autentico/pkg/token"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// UserFromRequest validates the bearer token on the request (JWT, session,
// revocation) and returns the owning user. Thin convenience wrapper over
// ValidateBearer for handlers that need the user rather than the raw
// Validated struct.
func UserFromRequest(r *http.Request) (*user.User, error) {
	v, err := ValidateBearer(r)
	if err != nil {
		return nil, err
	}
	usr, err := user.UserByID(v.Session.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %v", err)
	}
	return usr, nil
}

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
// middleware uses its own flow because it needs per-step RFC 6750 response
// mapping.
func ValidateBearer(r *http.Request) (*Validated, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, fmt.Errorf("missing Authorization header")
	}
	bearerToken := utils.ExtractBearerToken(authHeader)
	if bearerToken == "" {
		return nil, fmt.Errorf("invalid Authorization header")
	}
	claims, err := jwtutil.ValidateAccessToken(bearerToken)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %v", err)
	}
	sess, err := session.SessionByAccessToken(bearerToken)
	if err != nil {
		return nil, fmt.Errorf("invalid session: %v", err)
	}
	if sess.DeactivatedAt != nil {
		return nil, fmt.Errorf("session has been deactivated")
	}
	// RFC 7009: tokens can be individually revoked via /oauth2/revoke,
	// independent of session state. A missing row (sql.ErrNoRows) means
	// the token was never persisted — valid (not every flow persists) and
	// must not reject.
	tkn, err := token.TokenByAccessToken(bearerToken)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("token lookup failed: %v", err)
	}
	if tkn != nil && tkn.RevokedAt != nil {
		return nil, fmt.Errorf("token has been revoked")
	}
	return &Validated{Token: bearerToken, Claims: claims, Session: sess}, nil
}
