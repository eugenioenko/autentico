package token

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
)

func UserByAuthorizationCode(w http.ResponseWriter, request TokenRequest) (*user.User, *authcode.AuthCode, error) {
	err := ValidateTokenRequestAuthorizationCode(request)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", fmt.Sprintf("%v", err))
		return nil, nil, err
	}

	code, err := authcode.AuthCodeByCode(request.Code)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_grant", fmt.Sprintf("%v", err))
		return nil, nil, err
	}

	if code == nil || code.Used || code.RedirectURI != request.RedirectURI || time.Now().After(code.ExpiresAt) {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_grant", "Authorization code is invalid or has already been used")
		return nil, nil, fmt.Errorf("authorization code is invalid or has already been used")
	}

	// Validate that client_id matches the one used when the code was issued
	if code.ClientID != "" && code.ClientID != request.ClientID {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_grant", "Client ID mismatch")
		return nil, nil, fmt.Errorf("client ID mismatch")
	}

	// PKCE validation
	if code.CodeChallenge != "" {
		if request.CodeVerifier == "" {
			utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_grant", "code_verifier is required")
			return nil, nil, fmt.Errorf("code_verifier is required")
		}
		if !verifyCodeChallenge(code.CodeChallenge, code.CodeChallengeMethod, request.CodeVerifier) {
			utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
			return nil, nil, fmt.Errorf("PKCE verification failed")
		}
	}

	err = authcode.MarkAuthCodeAsUsed(request.Code)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", fmt.Sprintf("Failed to mark authorization code as used: %v", err))
		return nil, nil, err
	}

	usr, err := user.UserByID(code.UserID)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", fmt.Sprintf("%v", err))
		return nil, nil, err
	}
	return usr, code, nil
}

// verifyCodeChallenge validates the PKCE code_verifier against the stored code_challenge.
// For S256: BASE64URL(SHA256(code_verifier)) must equal code_challenge.
// For plain: code_verifier must equal code_challenge.
func verifyCodeChallenge(codeChallenge, method, codeVerifier string) bool {
	switch method {
	case "S256", "":
		// S256 is the default if no method specified but challenge exists
		hash := sha256.Sum256([]byte(codeVerifier))
		computed := base64.RawURLEncoding.EncodeToString(hash[:])
		return computed == codeChallenge
	case "plain":
		return codeVerifier == codeChallenge
	default:
		return false
	}
}
