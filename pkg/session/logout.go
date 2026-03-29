package session

import (
	"encoding/json"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	"github.com/eugenioenko/autentico/pkg/jwtutil"
	"github.com/eugenioenko/autentico/pkg/key"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// HandleLogout godoc
// @Summary Log out a user
// @Description Terminates the user's session
// @Tags session
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Success 200 {string} string "Session terminated successfully"
// @Failure 401 {object} model.ApiError
// @Failure 500 {object} model.ApiError
// @Router /oauth2/logout [post]
func HandleLogout(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "invalid_request", "Authorization header is required")
		return
	}

	accessToken := utils.ExtractBearerToken(authHeader)
	if accessToken == "" {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "invalid_request", "Invalid Authorization header")
		return
	}

	claims, err := jwtutil.ValidateAccessToken(accessToken)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "invalid_token", "Invalid or expired token")
		return
	}

	query := `
		UPDATE sessions
		SET deactivated_at = CURRENT_TIMESTAMP
		WHERE access_token = ?;
	`
	_, err = db.GetDB().Exec(query, accessToken)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to terminate session")
		return
	}

	// Deactivate all IdP sessions for this user so SSO auto-login is revoked.
	// This covers both browser-initiated logout (cookie present) and
	// server-side logout (no cookie, but user ID is in the token claims).
	_ = idpsession.DeactivateAllForUser(claims.UserID)
	idpsession.ClearCookie(w)

	utils.SuccessResponse(w, "ok", http.StatusOK)
}

// idTokenHintClaims holds the claims we care about from an id_token_hint.
// Valid() always returns nil so that expired ID tokens are accepted per the spec.
type idTokenHintClaims struct {
	Subject  string `json:"sub"`
	ClientID string `json:"azp"` // authorized party
	RawAud   interface{}
}

func (c *idTokenHintClaims) Valid() error { return nil }

func (c *idTokenHintClaims) UnmarshalJSON(b []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if v, ok := raw["sub"].(string); ok {
		c.Subject = v
	}
	if v, ok := raw["azp"].(string); ok {
		c.ClientID = v
	}
	c.RawAud = raw["aud"]
	return nil
}

// audClientID returns the first audience value as a client_id candidate.
func (c *idTokenHintClaims) audClientID() string {
	switch v := c.RawAud.(type) {
	case string:
		return v
	case []interface{}:
		if len(v) > 0 {
			if s, ok := v[0].(string); ok {
				return s
			}
		}
	}
	return ""
}

// parseIDTokenHint parses an ID token hint without validating expiry.
// Returns nil claims (no error) when the hint is empty or unparseable — callers
// should treat missing claims as "no hint provided".
func parseIDTokenHint(hint string) *idTokenHintClaims {
	if hint == "" {
		return nil
	}
	claims := &idTokenHintClaims{}
	_, err := jwt.ParseWithClaims(hint, claims, func(t *jwt.Token) (interface{}, error) {
		return key.GetPublicKey(), nil
	})
	if err != nil {
		return nil
	}
	return claims
}

// HandleRpInitiatedLogout godoc
// @Summary RP-Initiated Logout (GET)
// @Description OIDC RP-Initiated Logout per OpenID Connect RP-Initiated Logout 1.0.
// @Description Clears the IdP session and optionally redirects to post_logout_redirect_uri.
// @Tags session
// @Produce html
// @Param id_token_hint query string false "Previously issued ID token"
// @Param post_logout_redirect_uri query string false "URI to redirect to after logout"
// @Param state query string false "Opaque value passed back to post_logout_redirect_uri"
// @Param client_id query string false "Client identifier (used to validate post_logout_redirect_uri when no id_token_hint)"
// @Success 302 {string} string "Redirect"
// @Router /oauth2/logout [get]
func HandleRpInitiatedLogout(w http.ResponseWriter, r *http.Request) {
	idTokenHint := r.URL.Query().Get("id_token_hint")
	postLogoutRedirectURI := r.URL.Query().Get("post_logout_redirect_uri")
	state := r.URL.Query().Get("state")
	clientIDParam := r.URL.Query().Get("client_id")

	// Parse the ID token hint (expired tokens are accepted per spec).
	hints := parseIDTokenHint(idTokenHint)

	// Determine user and deactivate their sessions if we have a subject.
	if hints != nil && hints.Subject != "" {
		query := `UPDATE sessions SET deactivated_at = CURRENT_TIMESTAMP WHERE user_id = ? AND deactivated_at IS NULL`
		_, _ = db.GetDB().Exec(query, hints.Subject)
		_ = idpsession.DeactivateAllForUser(hints.Subject)
	}

	// Always clear the IdP session cookie regardless of token hint.
	idpsession.ClearCookie(w)

	// Resolve which client to use for post_logout_redirect_uri validation.
	resolvedClientID := clientIDParam
	if resolvedClientID == "" && hints != nil {
		if hints.ClientID != "" {
			resolvedClientID = hints.ClientID
		} else {
			resolvedClientID = hints.audClientID()
		}
	}

	// Validate post_logout_redirect_uri against the client's registered URIs.
	if postLogoutRedirectURI != "" && resolvedClientID != "" {
		c, err := client.ClientByClientID(resolvedClientID)
		if err == nil {
			for _, allowed := range c.GetPostLogoutRedirectURIs() {
				if allowed == postLogoutRedirectURI {
					target := postLogoutRedirectURI
					if state != "" {
						target += "?state=" + state
					}
					http.Redirect(w, r, target, http.StatusFound)
					return
				}
			}
		}
	}

	// Fall back to the app root if no valid redirect URI was provided.
	http.Redirect(w, r, "/", http.StatusFound)
}
