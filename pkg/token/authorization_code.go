package token

import (
	"fmt"
	"net/http"
	"time"

	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
)

func UserByAuthorizationCode(w http.ResponseWriter, request TokenRequest) (*user.User, error) {
	err := ValidateTokenRequestAuthorizationCode(request)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", fmt.Sprintf("%v", err))
		return nil, err
	}

	code, err := authcode.AuthCodeByCode(request.Code)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_grant", fmt.Sprintf("%v", err))
		return nil, err
	}

	if code == nil || code.Used || code.RedirectURI != request.RedirectURI || time.Now().After(code.ExpiresAt) {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_grant", "Authorization code is invalid or has already been used")
		return nil, err
	}

	err = authcode.MarkAuthCodeAsUsed(request.Code)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", fmt.Sprintf("Failed to mark authorization code as used: %v", err))
		return nil, err
	}

	usr, err := user.UserByID(code.UserID)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", fmt.Sprintf("%v", err))
		return nil, err
	}
	return usr, nil
}
