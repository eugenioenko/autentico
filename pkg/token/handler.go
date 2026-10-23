package token

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/eugenioenko/autentico/pkg/audit"
	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/idpsession"
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
// @Failure 401 {object} model.AuthErrorResponse "Client authentication failed; matching WWW-Authenticate challenge"
// @Failure 500 {object} model.ApiError
// @Router /oauth2/token [post]
func HandleToken(w http.ResponseWriter, r *http.Request) {
	// RFC 6749 §3.2: the client MUST use the HTTP POST method at the token endpoint
	if r.Method != http.MethodPost {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Only POST method is allowed")
		return
	}

	// RFC 6749 §4.1.3 / Appendix B: token request parameters use application/x-www-form-urlencoded
	err := r.ParseForm()
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Request payload needs to be application/x-www-form-urlencoded")
		return
	}

	// RFC 6749 §2.3.1: the shared authenticator resolves Basic credentials;
	// form credentials come only from the body, never from the URL.
	request := TokenRequest{
		GrantType:    r.FormValue("grant_type"),
		Code:         r.FormValue("code"),
		RedirectURI:  r.FormValue("redirect_uri"),
		ClientID:     r.PostForm.Get("client_id"),
		ClientSecret: r.PostForm.Get("client_secret"),
		CodeVerifier: r.FormValue("code_verifier"),
		Username:     r.FormValue("username"),
		Password:     r.FormValue("password"),
		TotpCode:     r.FormValue("totp_code"),
		RefreshToken: r.FormValue("refresh_token"),
		Scope:        r.FormValue("scope"),
		DeviceCode:   r.FormValue("device_code"),
	}

	err = ValidateTokenRequest(request)
	if err != nil {
		// RFC 6749 §5.2: this validator checks only grant_type. A missing
		// value is invalid_request; a nonempty unsupported value has its own
		// error, before client-specific grant permissions are considered.
		if request.GrantType != "" {
			utils.WriteErrorResponse(w, http.StatusBadRequest, "unsupported_grant_type", "Grant type is not supported")
			return
		}
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", fmt.Sprintf("%v", err))
		return
	}

	// Authenticate client (validates client_id if one is provided)
	var authenticatedClient *client.Client
	authenticatedClient, err = client.AuthenticateClientFromRequest(r)
	if err != nil {
		// RFC 6749 §5.2: malformed authentication differs from bad credentials.
		if errors.Is(err, client.ErrInvalidClientAuthenticationRequest) {
			utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		slog.Warn("token: invalid client credentials", "request_id", reqid.Get(r.Context()), "client_id", request.ClientID, "ip", utils.GetClientIP(r), "error", err)
		// RFC 6749 §5.2: challenge failed client authentication with HTTP 401.
		utils.WriteBasicUnauthorized(w, "token", err.Error())
		return
	}

	// RFC 6749 §2.3.1 / §4.1.3: all grant bindings and issued claims use the
	// authenticated registration, not the still-encoded Basic username.
	if authenticatedClient != nil {
		request.ClientID = authenticatedClient.ClientID
	}

	// If a client was resolved, validate that it allows the requested grant type
	// RFC 6749 §5.2: unauthorized_client: the client is not authorized to use this grant type
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
		// RFC 6749 §4.3.2: username and password are REQUIRED; missing parameters are invalid_request
		err = ValidateTokenRequestPassword(request)
		if err != nil {
			utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", fmt.Sprintf("%v", err))
			return
		}

		// RFC 6749 §4.3.2 / §5.2: the client must be identified (and authenticated if
		// confidential); an unidentified client is invalid_client.
		if authenticatedClient == nil {
			utils.WriteBasicUnauthorized(w, "token", "client_id is required for password grant")
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
			utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_grant", "Invalid username or password")
			return
		}
		// Enforce MFA on password grant when required or when user has TOTP enrolled.
		cfg := config.Get()
		// RFC 6749 §4.3.2 / §5.2: enforce local account eligibility before
		// issuing a grant. Match browser email policy and its admin exemption.
		if cfg.RequireEmailVerification && !usr.IsEmailVerified && usr.Role != "admin" {
			utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_grant", "Email verification is required")
			return
		}
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
			if err := mfa.VerifyPasswordGrantTotp(usr.ID, request.TotpCode); err != nil {
				switch {
				case errors.Is(err, mfa.ErrTotpLocked):
					audit.Log(audit.EventMfaFailed, nil, audit.TargetUser, usr.ID,
						audit.Detail("method", "totp", "grant_type", "password", "reason", "account_attempts_exhausted"), utils.GetClientIP(r))
					utils.WriteErrorResponse(w, http.StatusForbidden, "mfa_locked", err.Error())
				case errors.Is(err, mfa.ErrInvalidTotp):
					slog.Warn("token: invalid MFA code (ROPC)", "request_id", reqid.Get(r.Context()), "user_id", usr.ID)
					utils.WriteErrorResponse(w, http.StatusForbidden, "invalid_mfa_code", "Invalid TOTP code")
				default:
					slog.Error("token: failed to verify MFA (ROPC)", "request_id", reqid.Get(r.Context()), "error", err)
					utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to verify TOTP code")
				}
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
		// RFC 6749 §3.3 / §5.2: invalid_scope: scope exceeds what the client may request
		if !client.ValidateScopes(authenticatedClient, requestedScope) {
			slog.Warn("token: invalid scope for client (ROPC)", "request_id", reqid.Get(r.Context()), "client_id", request.ClientID, "scope", requestedScope)
			utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_scope", "One or more requested scopes are not allowed for this client")
			return
		}
		codeScope = requestedScope
		codeAuthTime = time.Now()

	case "client_credentials":
		// RFC 6749 §4.4.2: the client MUST authenticate with the authorization server
		if authenticatedClient == nil {
			utils.WriteBasicUnauthorized(w, "token", "Client authentication is required for client_credentials grant")
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
		// RFC 6749 §3.3 / §5.2: invalid_scope: no usable scope remains for this grant
		if ccScope == "" {
			utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_scope", "No valid scopes requested")
			return
		}
		// RFC 6749 §4.4.2 / §5.2: invalid_scope: scope exceeds what the client may request
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
			utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Token generation failed")
			return
		}

		// Store token with NULL user_id
		ccErr = CreateToken(Token{
			ClientID:              ccToken.ClientID,
			ACR:                   ccToken.ACR,
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
			utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to store token")
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

	case "urn:ietf:params:oauth:grant-type:device_code":
		usr, codeScope, err = handleDeviceCodeGrant(w, r, request)
		if err != nil {
			return
		}

	case "refresh_token":
		// RFC 6749 §6 / §10.4: identify and authenticate the registered issuing client.
		if authenticatedClient == nil {
			utils.WriteBasicUnauthorized(w, "token", "client_id is required for refresh_token grant")
			return
		}
		grant, refreshErr := readRefreshGrant(w, request)
		if refreshErr != nil {
			return
		}
		usr = grant.user
		if grant.session.IdpSessionID != nil {
			idpSessionID = *grant.session.IdpSessionID
		}
		// OIDC Core §12.2: refreshed tokens retain the original authentication.
		codeAuthTime, err = grant.authenticationTime()
		if err != nil {
			utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_grant", "Original authentication is unavailable. Please sign in again.")
			return
		}
		tokenScope := grant.scope

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

	authToken, err := generateTokens(*usr, request.ClientID, codeScope, clientCfg, codeAuthTime)
	if err != nil {
		slog.Error("token: failed to generate tokens", "request_id", reqid.Get(r.Context()), "error", err)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Token generation failed")
		return
	}

	tokenRow := Token{
		ClientID:              authToken.ClientID,
		ACR:                   authToken.ACR,
		UserID:                &authToken.UserID,
		AccessToken:           authToken.AccessToken,
		RefreshToken:          authToken.RefreshToken,
		AccessTokenType:       "Bearer",
		RefreshTokenExpiresAt: authToken.RefreshExpiresAt,
		AccessTokenExpiresAt:  authToken.AccessExpiresAt,
		IssuedAt:              time.Now().UTC(),
		Scope:                 codeScope,
		GrantType:             request.GrantType,
	}

	// RFC 6749 §6 / RFC 9700 §4.14.2: retain the session and replay linkage
	// until both credentials expire, including when access outlives refresh.
	sessionExpiresAt := authToken.AccessExpiresAt
	if authToken.RefreshExpiresAt.After(sessionExpiresAt) {
		sessionExpiresAt = authToken.RefreshExpiresAt
	}
	sessionRow := session.Session{
		ID:           authToken.SessionID,
		UserID:       authToken.UserID,
		AccessToken:  authToken.AccessToken,
		RefreshToken: authToken.RefreshToken,
		UserAgent:    r.UserAgent(),
		IPAddress:    utils.GetClientIP(r),
		ExpiresAt:    sessionExpiresAt.UTC(),
	}
	if idpSessionID != "" {
		sessionRow.IdpSessionID = &idpSessionID
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
			utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Token generation failed")
			return
		}
		response.IDToken = idToken
	}

	// RFC 6749 §4.1.2 / §6 and RFC 8628 §3.5: claim single-use credentials
	// and persist their token/session pair in one transaction, after all validation.
	if err := storeGrantTokens(request, tokenRow, sessionRow); err != nil {
		if errors.Is(err, errGrantConsumed) {
			var revokeErr error
			switch request.GrantType {
			case "authorization_code":
				revokeErr = revokeAuthorizationGrant(usr.ID, request.ClientID, idpSessionID)
			case "refresh_token":
				revokeErr = revokeRefreshFamily(usr.ID)
			}
			if revokeErr != nil {
				slog.Error("token: failed to revoke replayed grant", "request_id", reqid.Get(r.Context()), "error", revokeErr)
			}
			// RFC 6749 §4.1.2 / §5.2: a reused grant MUST be denied with invalid_grant;
			// tokens previously issued from it SHOULD be revoked (done above).
			utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_grant", "Grant has already been used or revoked")
		} else if errors.Is(err, errGrantExpired) {
			// RFC 6749 §5.2: invalid_grant: the grant has expired
			utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_grant", "Grant has expired")
		} else {
			slog.Error("token: failed to persist grant issuance", "request_id", reqid.Get(r.Context()), "error", err)
			utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to issue tokens")
		}
		return
	}
	if request.GrantType == "refresh_token" && idpSessionID != "" {
		// Successful refresh is user activity; failed issuance does not extend a session.
		_ = idpsession.UpdateLastActivity(idpSessionID)
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
