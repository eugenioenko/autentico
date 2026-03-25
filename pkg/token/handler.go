package token

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/middleware"
	"github.com/eugenioenko/autentico/pkg/session"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// HandleToken godoc
// @Summary Token endpoint
// @Description Exchanges authorization code or credentials for tokens
// @Tags token
// @Accept application/x-www-form-urlencoded
// @Produce json
// @Param grant_type formData string true "Grant type"
// @Param code formData string false "Authorization code"
// @Param redirect_uri formData string false "Redirect URI"
// @Param client_id formData string false "Client ID"
// @Param username formData string false "Username"
// @Param password formData string false "Password"
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
		slog.Warn("token: invalid client credentials", "request_id", middleware.GetRequestID(r.Context()), "client_id", request.ClientID, "ip", utils.GetClientIP(r), "error", err)
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}

	// If a client was resolved, validate that it allows the requested grant type
	if authenticatedClient != nil && !client.IsGrantTypeAllowed(authenticatedClient, request.GrantType) {
		slog.Warn("token: grant type not allowed for client", "request_id", middleware.GetRequestID(r.Context()), "client_id", request.ClientID, "grant_type", request.GrantType)
		utils.WriteErrorResponse(w, http.StatusBadRequest, "unauthorized_client", "Grant type not allowed for this client")
		return
	}

	var usr *user.User
	var codeNonce string
	var codeScope string
	codeAuthTime := time.Now()

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
				slog.Warn("token: account locked (ROPC)", "request_id", middleware.GetRequestID(r.Context()), "ip", utils.GetClientIP(r))
				utils.WriteErrorResponse(w, http.StatusForbidden, "account_locked", err.Error())
				return
			}
			slog.Warn("token: invalid ROPC credentials", "request_id", middleware.GetRequestID(r.Context()), "ip", utils.GetClientIP(r))
			utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_grant", fmt.Sprintf("Invalid username or password: %v", err))
			return
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
			slog.Warn("token: invalid scope for client (ROPC)", "request_id", middleware.GetRequestID(r.Context()), "client_id", request.ClientID, "scope", requestedScope)
			utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_scope", "One or more requested scopes are not allowed for this client")
			return
		}
		codeScope = requestedScope

	case "refresh_token":
		usr, err = UserByRefreshToken(w, request)
		if err != nil {
			return
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

	authToken, err := GenerateTokens(*usr, request.ClientID, clientCfg)
	if err != nil {
		slog.Error("token: failed to generate tokens", "request_id", middleware.GetRequestID(r.Context()), "error", err)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", fmt.Sprintf("Token generation failed: %v", err))
		return
	}

	err = CreateToken(Token{
		UserID:                authToken.UserID,
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
		slog.Error("token: failed to store token", "request_id", middleware.GetRequestID(r.Context()), "error", err)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", fmt.Sprintf("%v", err))
		return
	}

	err = session.CreateSession(session.Session{
		ID:           authToken.SessionID,
		UserID:       authToken.UserID,
		AccessToken:  authToken.AccessToken,
		RefreshToken: authToken.RefreshToken,
		UserAgent:    r.UserAgent(),
		IPAddress:    utils.GetClientIP(r),
		ExpiresAt:    authToken.AccessExpiresAt.UTC(),
	})

	if err != nil {
		slog.Error("token: failed to create session", "request_id", middleware.GetRequestID(r.Context()), "error", err)
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

	// Generate ID token when "openid" scope is requested
	if containsScope(codeScope, "openid") {
		idToken, idErr := GenerateIDToken(*usr, authToken.SessionID, codeNonce, codeScope, request.ClientID, codeAuthTime)
		if idErr != nil {
			slog.Error("token: failed to generate ID token", "request_id", middleware.GetRequestID(r.Context()), "error", idErr)
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
