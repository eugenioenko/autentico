package introspect

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/jwtutil"
	"github.com/eugenioenko/autentico/pkg/middleware"
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
// @Tags introspect
// @Accept json
// @Produce json
// @Param token body IntrospectRequest true "Token introspection payload"
// @Success 200 {object} IntrospectResponse
// @Failure 400 {object} model.ApiError
// @Failure 401 {object} model.ApiError
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
		slog.Warn("introspect: client authentication failed", "request_id", middleware.GetRequestID(r.Context()), "error", err)
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "invalid_client", "Client authentication failed")
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
		bearerToken := utils.ExtractBearerToken(r.Header.Get("Authorization"))
		if bearerToken == "" {
			utils.WriteErrorResponse(w, http.StatusUnauthorized, "invalid_client", "Client authentication required")
			return
		}
		claims, err := jwtutil.ValidateAccessToken(bearerToken)
		if err != nil {
			slog.Warn("introspect: bearer token invalid", "request_id", middleware.GetRequestID(r.Context()), "error", err)
			utils.WriteErrorResponse(w, http.StatusUnauthorized, "invalid_token", "Bearer token is invalid or expired")
			return
		}
		usr, err := user.UserByID(claims.UserID)
		if err != nil || usr.Role != "admin" {
			slog.Warn("introspect: bearer auth requires admin role", "request_id", middleware.GetRequestID(r.Context()), "user_id", claims.UserID)
			utils.WriteErrorResponse(w, http.StatusForbidden, "insufficient_scope", "Admin access required for bearer token introspection")
			return
		}
	}

	var req IntrospectRequest

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
		slog.Info("introspect: inactive token", "request_id", middleware.GetRequestID(r.Context()), "reason", err)
		inactive(w)
		return
	}

	// RFC 6749 §4.4: client_credentials tokens have no session — skip session liveness check
	if tkn.GrantType != "client_credentials" {
		// RFC 7662 §4: check session liveness — deactivated sessions mean the token
		// should no longer be considered active.
		sess, err := session.SessionByAccessToken(tkn.AccessToken)
		if err != nil || sess == nil || sess.DeactivatedAt != nil {
			slog.Info("introspect: session not active", "request_id", middleware.GetRequestID(r.Context()))
			inactive(w)
			return
		}
	}

	// RFC 7662 §2.2: tokens that are "otherwise invalid" SHOULD return active=false.
	// A deactivated user's tokens are no longer valid by server policy.
	if tkn.UserID != nil {
		usr, err := user.UserByIDIncludingDeactivated(*tkn.UserID)
		if err != nil || usr == nil || usr.DeactivatedAt != nil {
			slog.Info("introspect: user deactivated or not found", "request_id", middleware.GetRequestID(r.Context()))
			inactive(w)
			return
		}
	}

	// RFC 7662 §2.2: active token response — "active" is REQUIRED, all other fields OPTIONAL.
	// Note: client_id and username are not stored in the tokens table — omitted per spec allowance.
	aud := strings.Join(config.Get().AuthAccessTokenAudience, " ")
	sub := ""
	if tkn.UserID != nil {
		sub = *tkn.UserID
	}
	introspect := IntrospectResponse{
		Active:    true,
		Scope:     tkn.Scope,
		TokenType: tkn.AccessTokenType,
		Exp:       tkn.AccessTokenExpiresAt.Unix(),
		Iat:       tkn.IssuedAt.Unix(),
		Sub:       sub,
		Iss:       config.GetBootstrap().AppAuthIssuer,
		Aud:       aud,
		Jti:       tkn.ID,
	}

	utils.WriteApiResponse(w, introspect, http.StatusOK)
}
