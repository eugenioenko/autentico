package token

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/mfa"
	"github.com/eugenioenko/autentico/pkg/reqid"
	"github.com/eugenioenko/autentico/pkg/session"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// HandleToken godoc
// @Summary Token endpoint
// @Description Exchanges authorization code or credentials for tokens
// @Tags oauth2
// @Accept application/x-www-form-urlencoded
// @Produce json
// @Param grant_type formData string true "Grant type (authorization_code, password, refresh_token, client_credentials)"
// @Param code formData string false "Authorization code"
// @Param redirect_uri formData string false "Redirect URI"
// @Param client_id formData string false "Client ID"
// @Param username formData string false "Username"
// @Param password formData string false "Password"
// @Param scope formData string false "Requested scope"
// @Success 200 {object} TokenResponse
// @Failure 400 {object} model.ApiError
// @Failure 500 {object} model.ApiError
// @Router /oauth2/token [post]
func HandleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Only POST method is allowed")
		return
	}

	err := r.ParseForm()
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Request payload needs to be application/x-www-form-urlencoded")
		return
	}

	// Extract client credentials from Basic Auth or form params
	var clientID, clientSecret string
	if user, pass, ok := r.BasicAuth(); ok {
		clientID = user
		clientSecret = pass
	} else {
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}

	request := TokenRequest{
		GrantType:    r.FormValue("grant_type"),
		Code:         r.FormValue("code"),
		RedirectURI:  r.FormValue("redirect_uri"),
		ClientID:     clientID,
		ClientSecret: clientSecret,
		CodeVerifier: r.FormValue("code_verifier"),
		Username:     r.FormValue("username"),
		Password:     r.FormValue("password"),
		TotpCode:     r.FormValue("totp_code"),
		RefreshToken: r.FormValue("refresh_token"),
		Scope:        r.FormValue("scope"),
	}

	err = ValidateTokenRequest(request)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", fmt.Sprintf("%v", err))
		return
	}

	// Authenticate client (validates client_id if one is provided)
	var authenticatedClient *client.Client
	authenticatedClient, err = client.AuthenticateClientFromRequest(r)
	if err != nil {
		slog.Warn("token: invalid client credentials", "request_id", reqid.Get(r.Context()), "client_id", request.ClientID, "ip", utils.GetClientIP(r), "error", err)
		// RFC 6749 §5.2: invalid_client MUST use HTTP 401; all other errors use HTTP 400
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}

	// If a client was resolved, validate that it allows the requested grant type
	if authenticatedClient != nil && !client.IsGrantTypeAllowed(authenticatedClient, request.GrantType) {
		slog.Warn("token: grant type not allowed for client", "request_id", reqid.Get(r.Context()), "client_id", request.ClientID, "grant_type", request.GrantType)
		utils.WriteErrorResponse(w, http.StatusBadRequest, "unauthorized_client", "Grant type not allowed for this client")
		return
	}

	var usr *user.User
	var codeNonce string
	var codeScope string
	codeAuthTime := time.Now()
	// idpSessionID links the new session/token back to the IdP (SSO) session
	// that authorized the user at /authorize. Empty for ROPC / client_credentials.
	var idpSessionID string

	switch request.GrantType {
	case "authorization_code":
		var code *authcode.AuthCode
		usr, code, err = UserByAuthorizationCode(w, request)
		if err != nil {
			return
		}
		codeNonce = code.Nonce
		codeScope = code.Scope
		codeAuthTime = code.CreatedAt
		idpSessionID = code.IdpSessionID
	case "password":
		err = ValidateTokenRequestPassword(request)
		if err != nil {
			utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", fmt.Sprintf("%v", err))
			return
		}

		if authenticatedClient == nil {
			utils.WriteErrorResponse(w, http.StatusUnauthorized, "invalid_client", "client_id is required for password grant")
			return
		}

		usr, err = user.AuthenticateUser(request.Username, request.Password)
		if err != nil {
			if errors.Is(err, user.ErrAccountLocked) {
				slog.Warn("token: account locked (ROPC)", "request_id", reqid.Get(r.Context()), "ip", utils.GetClientIP(r))
				utils.WriteErrorResponse(w, http.StatusForbidden, "account_locked", err.Error())
				return
			}
			slog.Warn("token: invalid ROPC credentials", "request_id", reqid.Get(r.Context()), "ip", utils.GetClientIP(r))
			// RFC 6749 §4.3.2: invalid credentials in ROPC MUST return invalid_grant (not invalid_client)
			utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_grant", fmt.Sprintf("Invalid username or password: %v", err))
			return
		}
		// Enforce MFA on password grant when required or when user has TOTP enrolled.
		cfg := config.Get()
		if cfg.RequireMfa || usr.TotpVerified {
			if !usr.TotpVerified {
				// MFA is required but user has not enrolled — they must enroll via browser flow first.
				slog.Warn("token: MFA required but not enrolled (ROPC)", "request_id", reqid.Get(r.Context()), "user_id", usr.ID)
				utils.WriteErrorResponse(w, http.StatusForbidden, "mfa_required", "MFA is required but not enrolled. Please enroll via the login page.")
				return
			}
			if request.TotpCode == "" {
				// User has TOTP enrolled but no code provided.
				slog.Info("token: MFA code required (ROPC)", "request_id", reqid.Get(r.Context()), "user_id", usr.ID)
				utils.WriteErrorResponse(w, http.StatusForbidden, "mfa_required", "TOTP code is required")
				return
			}
			if !mfa.ValidateTotpCode(usr.TotpSecret, request.TotpCode) {
				slog.Warn("token: invalid MFA code (ROPC)", "request_id", reqid.Get(r.Context()), "user_id", usr.ID)
				utils.WriteErrorResponse(w, http.StatusForbidden, "invalid_mfa_code", "Invalid TOTP code")
				return
			}
		}

		// Determine effective scope.
		// If no scope was requested, fall back to the client's full allowed scopes.
		requestedScope := request.Scope
		if requestedScope == "" && authenticatedClient != nil && authenticatedClient.Scopes != "" {
			requestedScope = authenticatedClient.Scopes
		}
		if requestedScope == "" {
			requestedScope = "openid profile email"
		}
		if !client.ValidateScopes(authenticatedClient, requestedScope) {
			slog.Warn("token: invalid scope for client (ROPC)", "request_id", reqid.Get(r.Context()), "client_id", request.ClientID, "scope", requestedScope)
			utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_scope", "One or more requested scopes are not allowed for this client")
			return
		}
		codeScope = requestedScope

	case "client_credentials":
		// RFC 6749 §4.4.2: the client MUST authenticate with the authorization server
		if authenticatedClient == nil {
			utils.WriteErrorResponse(w, http.StatusUnauthorized, "invalid_client", "Client authentication is required for client_credentials grant")
			return
		}
		// RFC 6749 §4.4.2: only confidential clients may use client_credentials
		if authenticatedClient.ClientType != "confidential" {
			utils.WriteErrorResponse(w, http.StatusBadRequest, "unauthorized_client", "Public clients cannot use client_credentials grant")
			return
		}

		// Resolve effective scope
		ccScope := request.Scope
		if ccScope == "" && authenticatedClient.Scopes != "" {
			ccScope = authenticatedClient.Scopes
		}
		// Strip "openid" — no user identity to assert in client_credentials
		ccScope = removeScope(ccScope, "openid")
		if ccScope == "" {
			utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_scope", "No valid scopes requested")
			return
		}
		if !client.ValidateScopes(authenticatedClient, ccScope) {
			slog.Warn("token: invalid scope for client (client_credentials)", "request_id", reqid.Get(r.Context()), "client_id", request.ClientID, "scope", ccScope)
			utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_scope", "One or more requested scopes are not allowed for this client")
			return
		}

		// Resolve per-client config overrides
		ccCfg := config.Get()
		if authenticatedClient != nil {
			resolved := config.GetForClient(authenticatedClient.ToOverrides())
			ccCfg = &resolved
		}

		ccToken, ccErr := GenerateClientCredentialsToken(request.ClientID, ccScope, ccCfg)
		if ccErr != nil {
			slog.Error("token: failed to generate client_credentials token", "request_id", reqid.Get(r.Context()), "error", ccErr)
			utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", fmt.Sprintf("Token generation failed: %v", ccErr))
			return
		}

		// Store token with NULL user_id
		ccErr = CreateToken(Token{
			UserID:                nil,
			AccessToken:           ccToken.AccessToken,
			RefreshToken:          "",
			AccessTokenType:       "Bearer",
			RefreshTokenExpiresAt: ccToken.AccessExpiresAt,
			AccessTokenExpiresAt:  ccToken.AccessExpiresAt,
			IssuedAt:              time.Now().UTC(),
			Scope:                 ccScope,
			GrantType:             "client_credentials",
		})
		if ccErr != nil {
			slog.Error("token: failed to store client_credentials token", "request_id", reqid.Get(r.Context()), "error", ccErr)
			utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", fmt.Sprintf("%v", ccErr))
			return
		}

		// RFC 6749 §4.4.3: response MUST include access_token, token_type; refresh token SHOULD NOT be included
		ccResponse := TokenResponse{
			AccessToken: ccToken.AccessToken,
			TokenType:   "Bearer",
			ExpiresIn:   int(ccCfg.AuthAccessTokenExpiration / time.Second),
			Scope:       ccScope,
		}

		// RFC 6749 §5.1: token responses must not be cached
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		utils.WriteApiResponse(w, ccResponse, http.StatusOK)
		return

	case "refresh_token":
		usr, err = UserByRefreshToken(w, request)
		if err != nil {
			return
		}
		// Carry the IdP session id forward so a refreshed session stays linked to
		// the same browser login. Without this, a refresh would orphan the new
		// session from the cascade and let a revoked IdP session produce live
		// tokens at the next refresh.
		var priorIdp *string
		_ = db.GetDB().QueryRow(
			`SELECT idp_session_id FROM sessions WHERE refresh_token = ?`,
			request.RefreshToken,
		).Scan(&priorIdp)
		if priorIdp != nil {
			idpSessionID = *priorIdp
		}
		// RFC 6819 §5.2.2.3 / OAuth 2.1 §6.1: rotate refresh token — revoke old, issue new.
		// The old token is invalidated so it cannot be reused. If a revoked token is
		// later presented, UserByRefreshToken detects the replay and revokes all user tokens.
		_, _ = db.GetDB().Exec(
			`UPDATE tokens SET revoked_at = ? WHERE refresh_token = ? AND revoked_at IS NULL`,
			time.Now().UTC(), request.RefreshToken,
		)
		// RFC 6749 §5.1: scope must be included in the response when it may differ
		// from what the client originally requested. Look up the scope and issued_at
		// stored with the original token.
		var tokenScope string
		var tokenIssuedAt time.Time
		_ = db.GetDB().QueryRow(`SELECT scope, issued_at FROM tokens WHERE refresh_token = ?`, request.RefreshToken).Scan(&tokenScope, &tokenIssuedAt)
		// OIDC Core §12.2: auth_time in a refreshed ID token MUST match the original
		// authentication time, not the refresh time.
		if !tokenIssuedAt.IsZero() {
			codeAuthTime = tokenIssuedAt
		}
		// RFC 6749 §6: if scope is present on a refresh request, it MUST NOT exceed the original grant;
		// a subset is allowed (downscoping). If absent, the original scope is reused unchanged.
		if request.Scope != "" {
			if !isScopeSubset(request.Scope, tokenScope) {
				utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_scope", "Requested scope exceeds the scope of the original grant")
				return
			}
			codeScope = request.Scope
		} else {
			codeScope = tokenScope
		}
	default:
		utils.WriteErrorResponse(w, http.StatusBadRequest, "unsupported_grant_type", "The provided grant type is not supported")
		return
	}

	if usr == nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "unsupported_grant_type", "The provided grant type is not supported")
		return
	}

	// Resolve per-client config overrides (falls back to global settings if client is nil or has no overrides)
	clientCfg := config.Get()
	if authenticatedClient != nil {
		resolved := config.GetForClient(authenticatedClient.ToOverrides())
		clientCfg = &resolved
	}

	authToken, err := GenerateTokens(*usr, request.ClientID, codeScope, clientCfg)
	if err != nil {
		slog.Error("token: failed to generate tokens", "request_id", reqid.Get(r.Context()), "error", err)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", fmt.Sprintf("Token generation failed: %v", err))
		return
	}

	err = CreateToken(Token{
		UserID:                &authToken.UserID,
		AccessToken:           authToken.AccessToken,
		RefreshToken:          authToken.RefreshToken,
		AccessTokenType:       "Bearer",
		RefreshTokenExpiresAt: authToken.RefreshExpiresAt,
		AccessTokenExpiresAt:  authToken.AccessExpiresAt,
		IssuedAt:              time.Now().UTC(),
		Scope:                 codeScope,
		GrantType:             request.GrantType,
	})

	if err != nil {
		slog.Error("token: failed to store token", "request_id", reqid.Get(r.Context()), "error", err)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", fmt.Sprintf("%v", err))
		return
	}

	sessionRow := session.Session{
		ID:           authToken.SessionID,
		UserID:       authToken.UserID,
		AccessToken:  authToken.AccessToken,
		RefreshToken: authToken.RefreshToken,
		UserAgent:    r.UserAgent(),
		IPAddress:    utils.GetClientIP(r),
		ExpiresAt:    authToken.AccessExpiresAt.UTC(),
	}
	if idpSessionID != "" {
		sessionRow.IdpSessionID = &idpSessionID
	}
	err = session.CreateSession(sessionRow)

	if err != nil {
		slog.Error("token: failed to create session", "request_id", reqid.Get(r.Context()), "error", err)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", fmt.Sprintf("%v", err))
		return
	}

	response := TokenResponse{
		AccessToken:  authToken.AccessToken,
		RefreshToken: authToken.RefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(clientCfg.AuthAccessTokenExpiration / time.Second),
		Scope:        codeScope,
	}

	// OIDC Core §3.1.2.1: ID token is only issued when the "openid" scope is present.
	// Without "openid", this is a plain OAuth 2.0 request — no ID token is returned.
	if containsScope(codeScope, "openid") {
		idToken, idErr := GenerateIDToken(*usr, authToken.SessionID, codeNonce, codeScope, request.ClientID, codeAuthTime, authToken.AccessToken)
		if idErr != nil {
			slog.Error("token: failed to generate ID token", "request_id", reqid.Get(r.Context()), "error", idErr)
			utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", fmt.Sprintf("ID token generation failed: %v", idErr))
			return
		}
		response.IDToken = idToken
	}

	// cookie-only mode: send refresh token as HttpOnly cookie and strip from JSON response
	if config.GetBootstrap().AuthRefreshTokenCookieOnly {
		SetRefreshTokenCookie(w, response.RefreshToken)
		response.RefreshToken = ""
	}

	// RFC 6749 §5.1: token responses must not be cached
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	utils.WriteApiResponse(w, response, http.StatusOK)

}

// isScopeSubset reports whether every scope token in requested is present in original.
// RFC 6749 §6: a refresh request MUST NOT ask for scope broader than the original grant.
func isScopeSubset(requested, original string) bool {
	orig := make(map[string]bool)
	for _, s := range strings.Fields(original) {
		orig[s] = true
	}
	for _, s := range strings.Fields(requested) {
		if !orig[s] {
			return false
		}
	}
	return true
}
