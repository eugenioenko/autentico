package token

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/config"
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
	}

	err = ValidateTokenRequest(request)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", fmt.Sprintf("%v", err))
		return
	}

	// Authenticate client if client_id is provided
	var authenticatedClient *client.Client
	if request.ClientID != "" {
		authenticatedClient, err = client.AuthenticateClientFromRequest(r)
		if err != nil {
			utils.WriteErrorResponse(w, http.StatusUnauthorized, "invalid_client", err.Error())
			return
		}

		// If client was found, validate grant type
		if authenticatedClient != nil && !client.IsGrantTypeAllowed(authenticatedClient, request.GrantType) {
			utils.WriteErrorResponse(w, http.StatusBadRequest, "unauthorized_client", "Grant type not allowed for this client")
			return
		}
	}

	var usr *user.User
	var codeNonce string
	var codeScope string

	switch request.GrantType {
	case "authorization_code":
		var code *authcode.AuthCode
		usr, code, err = UserByAuthorizationCode(w, request)
		if err != nil {
			return
		}
		codeNonce = code.Nonce
		codeScope = code.Scope
	case "password":
		err = ValidateTokenRequestPassword(request)
		if err != nil {
			utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", fmt.Sprintf("%v", err))
			return
		}

		usr, err = user.AuthenticateUser(request.Username, request.Password)
		if err != nil {
			if errors.Is(err, user.ErrAccountLocked) {
				utils.WriteErrorResponse(w, http.StatusForbidden, "account_locked", err.Error())
				return
			}
			utils.WriteErrorResponse(w, http.StatusUnauthorized, "invalid_grant", fmt.Sprintf("Invalid username or password: %v", err))
			return
		}
		codeScope = "openid profile email"

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

	authToken, err := GenerateTokens(*usr)
	if err != nil {
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
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", fmt.Sprintf("%v", err))
		return
	}

	response := TokenResponse{
		AccessToken:  authToken.AccessToken,
		RefreshToken: authToken.RefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(config.Get().AuthAccessTokenExpiration / time.Second),
		Scope:        codeScope,
	}

	// Generate ID token when "openid" scope is requested
	if containsScope(codeScope, "openid") {
		idToken, idErr := GenerateIDToken(*usr, authToken.SessionID, codeNonce, codeScope, request.ClientID)
		if idErr != nil {
			utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", fmt.Sprintf("ID token generation failed: %v", idErr))
			return
		}
		response.IDToken = idToken
	}

	// send the refresh token as secure cookie
	if config.Get().AuthRefreshTokenAsSecureCookie {
		SetRefreshTokenAsSecureCookie(w, response.RefreshToken)
		response.RefreshToken = ""
	}

	utils.WriteApiResponse(w, response, http.StatusOK)

}
