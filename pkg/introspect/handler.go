package introspect

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/eugenioenko/autentico/pkg/bearer"
	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/jwtutil"
	"github.com/eugenioenko/autentico/pkg/reqid"
	"github.com/eugenioenko/autentico/pkg/session"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// inactive returns the RFC 7662 §2.2 required response for any token that is
// not active: HTTP 200 with {"active":false} and no additional claims.
func inactive(w http.ResponseWriter) {
	utils.WriteApiResponse(w, IntrospectResponse{Active: false}, http.StatusOK)
}

// HandleIntrospect godoc
// @Summary Introspect a token
// @Description Validates and retrieves metadata about a token
// @Tags oauth2
// @Accept json
// @Produce json
// @Param token body IntrospectRequest true "Token introspection payload"
// @Success 200 {object} IntrospectResponse
// @Failure 400 {object} model.ApiError
// @Failure 401 {object} model.ApiError
// @Failure 403 {object} model.ApiError "insufficient_scope; WWW-Authenticate: Bearer error=insufficient_scope"
// @Failure 429 {object} model.ApiError
// @Failure 500 {object} model.ApiError
// @Router /oauth2/introspect [post]
func HandleIntrospect(w http.ResponseWriter, r *http.Request) {

	// RFC 7662 §2.1: "To prevent token scanning attacks, the endpoint MUST also
	// require some form of authorization to access this endpoint, such as client
	// authentication as described in OAuth 2.0 [RFC6749] or a separate OAuth 2.0
	// access token such as the bearer token described in OAuth 2.0 Bearer Token
	// Usage [RFC6750]."
	authenticatedClient, err := client.AuthenticateClientFromRequest(r)
	if err != nil {
		// RFC 6749 §5.2 / RFC 7662 §2.3: reject ambiguous credentials.
		if errors.Is(err, client.ErrInvalidClientAuthenticationRequest) {
			utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		slog.Warn("introspect: client authentication failed", "request_id", reqid.Get(r.Context()), "error", err)
		w.Header().Set("WWW-Authenticate", `Basic realm="introspection"`)
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "invalid_client", "Client authentication failed")
		return
	}
	// RFC 7662 §2.1 / §4: a public client_id is not an authorization
	// credential for token scanning. Require authenticated confidential clients.
	if authenticatedClient != nil && authenticatedClient.ClientType != "confidential" {
		w.Header().Set("WWW-Authenticate", `Basic realm="introspection"`)
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "invalid_client", "Confidential client authentication required")
		return
	}
	if authenticatedClient == nil {
		// RFC 7662 §2.1: alternatively accept "a separate OAuth 2.0 access token
		// such as the bearer token described in OAuth 2.0 Bearer Token Usage [RFC6750]"
		//
		// RFC 7662 §4 (Security Considerations): "The authorization server MUST
		// determine whether or not the token can be introspected by the specific
		// resource server making the request." We restrict bearer auth to admin
		// users only to prevent arbitrary users from inspecting other users' tokens.
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="introspection"`)
			utils.WriteErrorResponse(w, http.StatusUnauthorized, "invalid_client", "Client authentication required")
			return
		}
		// RFC 6750 §3.1: an invalid bearer credential is invalid_token with HTTP 401
		v, err := bearer.ValidateBearer(r)
		if err != nil {
			slog.Warn("introspect: bearer auth failed", "request_id", reqid.Get(r.Context()), "error", err)
			utils.WriteBearerUnauthorized(w, config.GetBootstrap().AppAuthIssuer, "invalid_token", "Bearer token is invalid, expired, or its session has been revoked")
			return
		}
		// RFC 7662 §2.1 / §4 and RFC 6750 §5.2: require the same admin
		// audience as AdminAuthMiddleware, in addition to the current admin role.
		if err := jwtutil.ValidateAudience(v.Claims.Audience, []string{config.AdminClientID}); err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope"`)
			utils.WriteErrorResponse(w, http.StatusForbidden, "insufficient_scope", "Token not issued for admin API")
			return
		}
		// RFC 6750 §3.1: insufficient_scope with HTTP 403 when the token lacks the required privileges
		usr, err := user.UserByID(v.Claims.UserID)
		if err != nil || usr.Role != "admin" {
			slog.Warn("introspect: bearer auth requires admin role", "request_id", reqid.Get(r.Context()), "user_id", v.Claims.UserID)
			w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope"`)
			utils.WriteErrorResponse(w, http.StatusForbidden, "insufficient_scope", "Admin access required for bearer token introspection")
			return
		}
	}

	var req IntrospectRequest

	// RFC 7662 §2.1: the token parameter is carried in the POST body
	if r.Body == nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Request body is empty")
		return
	}

	// RFC 7662 §2.1: request MUST be application/x-www-form-urlencoded.
	// Also accept application/json for backwards compatibility with existing callers.
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		if err := r.ParseForm(); err != nil {
			utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid form data")
			return
		}
		// RFC 7662 §2.1: "token" parameter is REQUIRED
		req.Token = r.FormValue("token")
	} else {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid request payload")
			return
		}
	}

	// RFC 7662 §2.1: "token" is REQUIRED
	if req.Token == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Token is required")
		return
	}

	err = ValidateTokenIntrospectRequest(req)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	// RFC 7662 §2.2: any token that is invalid, expired, revoked, or unknown
	// MUST return 200 {"active":false} — never a 4xx error.
	tkn, err := IntrospectToken(req.Token)
	if err != nil {
		slog.Info("introspect: inactive token", "request_id", reqid.Get(r.Context()), "reason", err)
		inactive(w)
		return
	}

	// RFC 7662 §2.1: a client MUST only be able to introspect tokens issued to itself.
	// RFC 7662 §4: "The authorization server MUST determine whether or not the token
	// can be introspected by the specific resource server making the request."
	// Return inactive (not an error) to avoid leaking token existence per §2.2.
	// Admin bearer auth (authenticatedClient == nil) skips this — admins can introspect any token.
	if authenticatedClient != nil {
		azp := tkn.ClientID
		if azp != "" && azp != authenticatedClient.ClientID {
			slog.Info("introspect: token belongs to different client", "request_id", reqid.Get(r.Context()), "token_azp", azp, "caller", authenticatedClient.ClientID)
			inactive(w)
			return
		}
	}

	// RFC 6749 §4.4: client_credentials tokens have no session — skip session liveness check
	if tkn.GrantType != "client_credentials" {
		// RFC 7662 §4: check session liveness — deactivated sessions mean the token
		// should no longer be considered active.
		sess, err := session.SessionByAccessTokenHash(tkn.AccessTokenHash)
		if err != nil || sess == nil || sess.DeactivatedAt != nil {
			slog.Info("introspect: session not active", "request_id", reqid.Get(r.Context()))
			inactive(w)
			return
		}
	}

	// RFC 7662 §2.2: tokens that are "otherwise invalid" SHOULD return active=false.
	// A deactivated user's tokens are no longer valid by server policy.
	if tkn.UserID != nil {
		usr, err := user.UserByIDIncludingDeactivated(*tkn.UserID)
		if err != nil || usr == nil || usr.DeactivatedAt != nil {
			slog.Info("introspect: user deactivated or not found", "request_id", reqid.Get(r.Context()))
			inactive(w)
			return
		}
	}

	// RFC 7662 §2.2: active token response — "active" is REQUIRED, all other fields OPTIONAL.
	// aud and jti describe the exact credential that passed database and liveness
	// checks above; exp follows that access or refresh credential as well.
	aud, jti := tokenAudienceAndID(req.Token)
	sub := ""
	if tkn.UserID != nil {
		sub = *tkn.UserID
	}
	introspect := IntrospectResponse{
		Active:    true,
		Scope:     tkn.Scope,
		TokenType: tkn.AccessTokenType,
		Exp:       tokenExpiration(tkn, utils.HashToken(req.Token)).Unix(),
		Iat:       tkn.IssuedAt.Unix(),
		Sub:       sub,
		Iss:       config.GetBootstrap().AppAuthIssuer,
		Aud:       aud,
		Jti:       jti,
	}

	utils.WriteApiResponse(w, introspect, http.StatusOK)
}
