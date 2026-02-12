package token

import (
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
