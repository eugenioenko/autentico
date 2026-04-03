package session

import (
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/eugenioenko/autentico/pkg/audit"
	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	"github.com/eugenioenko/autentico/pkg/jwtutil"
	"github.com/eugenioenko/autentico/pkg/key"
	"github.com/eugenioenko/autentico/pkg/utils"
	"github.com/eugenioenko/autentico/view"
)

// HandleLogout godoc
// @Summary Log out a user (POST)
// @Description RP-Initiated Logout via POST (form-encoded) per OpenID Connect RP-Initiated Logout 1.0 §2.
// @Description Also accepts Bearer access token for backward-compatible programmatic logout.
// @Tags session
// @Accept application/x-www-form-urlencoded
// @Produce json
// @Produce html
// @Param Authorization header string false "Bearer access token (backward-compat extension)"
// @Param id_token_hint formData string false "Previously issued ID token"
// @Param client_id formData string false "Client identifier"
// @Param post_logout_redirect_uri formData string false "URI to redirect to after logout"
// @Param state formData string false "Opaque value passed back to post_logout_redirect_uri"
// @Success 200 {string} string "Session terminated successfully"
// @Success 302 {string} string "Redirect to post_logout_redirect_uri"
// @Failure 401 {object} model.ApiError
// @Failure 500 {object} model.ApiError
// @Router /oauth2/logout [post]
func HandleLogout(w http.ResponseWriter, r *http.Request) {
	// RP-Initiated Logout 1.0 §2: OPs MUST support the use of the HTTP GET and
	// POST methods at the Logout Endpoint. If using POST, the request parameters
	// are serialized using Form Serialization.

	// Backward compatibility: if a Bearer token is present, use it for
	// programmatic logout (non-spec extension).
	authHeader := r.Header.Get("Authorization")
	if bearerToken := utils.ExtractBearerToken(authHeader); bearerToken != "" {
		handleBearerLogout(w, r, bearerToken)
		return
	}

	// RP-Initiated Logout 1.0 §2: POST uses Form Serialization for the same
	// parameters as GET (id_token_hint, client_id, post_logout_redirect_uri, state).
	_ = r.ParseForm()
	rpInitiatedLogout(w, r,
		r.FormValue("id_token_hint"),
		r.FormValue("post_logout_redirect_uri"),
		r.FormValue("state"),
		r.FormValue("client_id"),
	)
}

// handleBearerLogout performs programmatic logout using a Bearer access token.
// This is a backward-compatible extension (not part of RP-Initiated Logout 1.0).
func handleBearerLogout(w http.ResponseWriter, r *http.Request, accessToken string) {
	realm := config.GetBootstrap().AppAuthIssuer

	claims, err := jwtutil.ValidateAccessToken(accessToken)
	if err != nil {
		// RFC 6750 §3.1: invalid_token when the token is expired, revoked, or malformed.
		utils.WriteBearerUnauthorized(w, realm, "invalid_token", "Invalid or expired token")
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

	audit.Log(audit.EventLogout, audit.SimpleActor{ID: claims.UserID}, audit.TargetUser, claims.UserID, nil, utils.GetClientIP(r))
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
// @Description OIDC RP-Initiated Logout per OpenID Connect RP-Initiated Logout 1.0 §2.
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
	// RP-Initiated Logout 1.0 §2: OPs MUST support the use of the HTTP GET and
	// POST methods at the Logout Endpoint. If using GET, request parameters are
	// serialized using URI Query String Serialization.
	rpInitiatedLogout(w, r,
		r.URL.Query().Get("id_token_hint"),
		r.URL.Query().Get("post_logout_redirect_uri"),
		r.URL.Query().Get("state"),
		r.URL.Query().Get("client_id"),
	)
}

// rpInitiatedLogout implements the core RP-Initiated Logout 1.0 logic shared
// by both GET (query params) and POST (form params) handlers.
func rpInitiatedLogout(w http.ResponseWriter, r *http.Request, idTokenHint, postLogoutRedirectURI, state, clientIDParam string) {
	// RP-Initiated Logout 1.0 §2: id_token_hint is RECOMMENDED. The OP SHOULD
	// accept ID Tokens when the RP has a current or recent session, even when
	// the exp time has passed.
	hints := parseIDTokenHint(idTokenHint)

	// RP-Initiated Logout 1.0 §2: When an id_token_hint is present, the OP MUST
	// validate that it was the issuer of the ID Token.
	// (parseIDTokenHint verifies the signature against our key, which proves we issued it.)

	// RP-Initiated Logout 1.0 §2: When both client_id and id_token_hint are
	// present, the OP MUST verify that the Client Identifier matches the one
	// used when issuing the ID Token.
	if clientIDParam != "" && hints != nil {
		hintClientID := hints.ClientID
		if hintClientID == "" {
			hintClientID = hints.audClientID()
		}
		if hintClientID != "" && hintClientID != clientIDParam {
			// RP-Initiated Logout 1.0 §4: If any validation fails, operations
			// requiring the failed information MUST be aborted and the OP MUST NOT
			// perform post-logout redirection.
			slog.Warn("session: client_id does not match id_token_hint",
				"client_id_param", clientIDParam, "hint_client_id", hintClientID)
			idpsession.ClearCookie(w)
			renderLogoutSuccess(w)
			return
		}
	}

	// Determine user and deactivate their sessions if we have a subject.
	if hints != nil && hints.Subject != "" {
		query := `UPDATE sessions SET deactivated_at = CURRENT_TIMESTAMP WHERE user_id = ? AND deactivated_at IS NULL`
		_, _ = db.GetDB().Exec(query, hints.Subject)
		_ = idpsession.DeactivateAllForUser(hints.Subject)
	}

	// RP-Initiated Logout 1.0 §2: Always clear the IdP session cookie regardless
	// of token hint presence.
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

	// RP-Initiated Logout 1.0 §3: post_logout_redirect_uri MUST have been
	// previously registered with the OP. The OP MUST NOT perform post-logout
	// redirection if the value does not exactly match a registered URI.
	if postLogoutRedirectURI != "" && resolvedClientID != "" {
		c, err := client.ClientByClientID(resolvedClientID)
		if err == nil {
			for _, allowed := range c.GetPostLogoutRedirectURIs() {
				if allowed == postLogoutRedirectURI {
					target := postLogoutRedirectURI
					if state != "" {
						target += "?state=" + state
					}
					// RP-Initiated Logout 1.0 §2: redirect to post_logout_redirect_uri
					// with optional state parameter.
					http.Redirect(w, r, target, http.StatusFound)
					return
				}
			}
		}
	}

	// RP-Initiated Logout 1.0 §4: When the OP detects errors or no valid
	// redirect URI is available, the OP MUST NOT perform post-logout redirection.
	// It MAY display a signed-out confirmation page.
	renderLogoutSuccess(w)
}

func renderLogoutSuccess(w http.ResponseWriter) {
	cfg := config.Get()
	tmpl, err := view.ParseTemplate("logout_success")
	if err != nil {
		slog.Error("session: failed to parse logout_success template", "error", err)
		http.Error(w, "You have been signed out.", http.StatusOK)
		return
	}
	data := map[string]any{
		"ThemeTitle":       cfg.Theme.Title,
		"ThemeLogoUrl":     cfg.Theme.LogoUrl,
		"ThemeCssResolved": template.CSS(cfg.ThemeCssResolved),
	}
	if err = tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		slog.Error("session: failed to execute logout_success template", "error", err)
	}
}
