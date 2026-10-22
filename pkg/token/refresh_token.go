package token

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	"github.com/eugenioenko/autentico/pkg/session"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// refreshGrant carries the claims and storage metadata already validated together.
type refreshGrant struct {
	user      *user.User
	session   *session.Session
	claims    *RefreshTokenClaims
	scope     string
	issuedAt  time.Time
	grantType string
}

// UserByRefreshToken retains the existing user lookup API for callers that do
// not issue a replacement grant.
func UserByRefreshToken(w http.ResponseWriter, request TokenRequest) (*user.User, error) {
	grant, err := readRefreshGrant(w, request)
	if err != nil {
		return nil, err
	}
	return grant.user, nil
}

// readRefreshGrant verifies the credential once and preserves its authenticated
// context for the token endpoint, without parsing discarded access JWTs.
func readRefreshGrant(w http.ResponseWriter, request TokenRequest) (*refreshGrant, error) {
	err := ValidateTokenRequestRefresh(request)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_grant", "Invalid or expired refresh token")
		return nil, err
	}

	// RFC 6749 §6 / §5.2: an invalid refresh token is invalid_grant
	authToken, err := DecodeRefreshToken(request.RefreshToken, config.GetBootstrap().AuthRefreshTokenSecret)
	if err != nil {
		slog.Warn("token: invalid refresh token", "error", err)
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_grant", "Invalid or expired refresh token")
		return nil, err
	}

	// RFC 6749 §5.2: invalid_grant: the refresh token has expired
	if time.Now().After(time.Unix(authToken.ExpiresAt, 0)) {
		slog.Warn("token: refresh token expired")
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_grant", "Refresh token has expired")
		return nil, fmt.Errorf("refresh token expired")
	}

	// RFC 6749 §5.2 / RFC 7009 §2.2: a refresh token whose session was revoked is invalid_grant
	sess, err := session.SessionByIDIncludingDeactivated(authToken.SessionID)
	if err != nil {
		slog.Warn("token: session not found for refresh token", "error", err, "session_id", authToken.SessionID)
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_grant", "Failed to retrieve session")
		return nil, err
	}

	if sess == nil || sess.DeactivatedAt != nil {
		slog.Warn("token: refresh token session deactivated", "session_id", authToken.SessionID)
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_grant", "Session has been deactivated")
		return nil, fmt.Errorf("session has been deactivated")
	}

	// RFC 6749 §10.4: refresh token MUST be bound to the client it was issued to;
	// unbound tokens and requests from a different client must not acquire a new binding.
	if authToken.ClientID == "" || authToken.ClientID != request.ClientID {
		slog.Warn("token: refresh token client mismatch", "token_client", authToken.ClientID, "request_client", request.ClientID)
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_grant", "Refresh token was not issued to this client")
		return nil, fmt.Errorf("refresh token client mismatch")
	}

	// Check if the token has been revoked.
	// RFC 6819 §5.2.2.3: a revoked refresh token being presented indicates that
	// token rotation occurred and someone (attacker or legitimate user) is replaying
	// a stale token. Revoke all tokens for this user as a protective measure.
	var revokedAt *time.Time
	var clientID, acr, accessHash, storedUserID, scope, grantType string
	var issuedAt time.Time
	err = db.GetDB().QueryRow(`SELECT revoked_at, client_id, acr, access_token_hash, COALESCE(user_id, ''), COALESCE(scope, ''), issued_at, COALESCE(grant_type, '')
		FROM tokens WHERE refresh_token_hash = ?`, utils.HashToken(request.RefreshToken)).Scan(
		&revokedAt, &clientID, &acr, &accessHash, &storedUserID, &scope, &issuedAt, &grantType)
	// RFC 6749 §6 and §5.2: validate the refresh token; missing records are invalid_grant.
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_grant", "Invalid or expired refresh token")
		return nil, fmt.Errorf("refresh token record unavailable: %w", err)
	}
	// RFC 6749 §6 and §10.4: enforce the token's stored client and resource-owner binding.
	if storedUserID != authToken.UserID || sess.UserID != authToken.UserID ||
		clientID != authToken.ClientID || sess.AccessTokenHash != accessHash ||
		sess.RefreshTokenHash != utils.HashToken(request.RefreshToken) {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_grant", "Invalid refresh token binding")
		return nil, fmt.Errorf("refresh token storage binding mismatch")
	}
	if revokedAt != nil {
		slog.Warn("token: rotated refresh token replayed — revoking all user tokens",
			"user_id", authToken.UserID)
		if err := revokeRefreshFamily(authToken.UserID); err != nil {
			slog.Error("token: failed to revoke all user tokens after replay detection", "error", err, "user_id", authToken.UserID)
		}
		// RFC 6749 §5.2: invalid_grant: the refresh token was revoked
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_grant", "Token has been revoked")
		return nil, fmt.Errorf("token has been revoked")
	}

	usr, err := user.UserByID(authToken.UserID)
	if err != nil {
		slog.Error("token: failed to retrieve user for refresh token", "error", err, "user_id", authToken.UserID)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to retrieve user")
		return nil, err
	}

	// Preserve the original authentication context even after the access JWT
	// has expired and its plaintext has been discarded.
	if usr.TotpVerified && acr != "2" {
		slog.Warn("token: refresh rejected — session was not MFA-authenticated", "user_id", usr.ID, "acr", acr)
		utils.WriteErrorResponse(w, http.StatusForbidden, "mfa_required", "Session was not authenticated with MFA. Please re-login.")
		return nil, fmt.Errorf("session not MFA-authenticated")
	}

	return &refreshGrant{user: usr, session: sess, claims: authToken, scope: scope, issuedAt: issuedAt, grantType: grantType}, nil
}

// authenticationTime recovers the original login for legacy browser grants and
// preserves signed authentication context on every subsequent rotation.
func (grant *refreshGrant) authenticationTime() (time.Time, error) {
	if grant.claims.AuthTime > 0 {
		// OIDC Core §12.2: authentication cannot postdate the signed issuance.
		if grant.claims.AuthTime > grant.claims.IssuedAt || grant.claims.AuthTime > time.Now().Unix() {
			return time.Time{}, fmt.Errorf("invalid refresh authentication time")
		}
		return time.Unix(grant.claims.AuthTime, 0), nil
	}
	if grant.claims.AuthTime < 0 {
		return time.Time{}, fmt.Errorf("invalid refresh authentication time")
	}
	if grant.session.IdpSessionID != nil && *grant.session.IdpSessionID != "" {
		browser, err := idpsession.IdpSessionByID(*grant.session.IdpSessionID)
		if err != nil {
			return time.Time{}, fmt.Errorf("original browser authentication is unavailable")
		}
		return grant.validateLegacyTime(browser.CreatedAt)
	}
	// An unrotated legacy password grant was authenticated at its issuance.
	// A legacy already-rotated unlinked grant has no recoverable original time.
	if grant.grantType == "password" && !grant.issuedAt.IsZero() {
		return grant.validateLegacyTime(grant.issuedAt)
	}
	return time.Time{}, fmt.Errorf("original authentication is unavailable; sign in again")
}

// validateLegacyTime rejects corrupt historical context before consuming a token.
func (grant *refreshGrant) validateLegacyTime(authenticated time.Time) (time.Time, error) {
	// OIDC Core §12.2: authentication must precede the original token issuance.
	if authenticated.IsZero() || authenticated.Unix() > grant.claims.IssuedAt || authenticated.After(time.Now()) {
		return time.Time{}, fmt.Errorf("invalid original authentication time")
	}
	return authenticated, nil
}
