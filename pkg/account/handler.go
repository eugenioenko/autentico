package account

import (
	"encoding/json"
	"net/http"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/mfa"
	"github.com/eugenioenko/autentico/pkg/passkey"
	"github.com/eugenioenko/autentico/pkg/session"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
	"golang.org/x/crypto/bcrypt"
)

func HandleGetProfile(w http.ResponseWriter, r *http.Request) {
	usr, err := user.GetUserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}
	utils.SuccessResponse(w, usr.ToResponse(), http.StatusOK)
}

func HandleUpdateProfile(w http.ResponseWriter, r *http.Request) {
	usr, err := user.GetUserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	var req user.UserUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	// We only allow updating Email and Username for now from this endpoint
	updateReq := user.UserUpdateRequest{
		Email:    req.Email,
		Username: req.Username,
	}

	if err := user.ValidateUserUpdateRequest(updateReq); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "validation_error", err.Error())
		return
	}

	if err := user.UpdateUser(usr.ID, updateReq); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	updated, _ := user.UserByID(usr.ID)
	utils.SuccessResponse(w, updated.ToResponse(), http.StatusOK)
}

func HandleUpdatePassword(w http.ResponseWriter, r *http.Request) {
	usr, err := user.GetUserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	var req UpdatePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	// Verify current password
	if err := bcrypt.CompareHashAndPassword([]byte(usr.Password), []byte(req.CurrentPassword)); err != nil {
		utils.WriteErrorResponse(w, http.StatusForbidden, "invalid_password", "Current password does not match")
		return
	}

	// Validate new password
	if err := user.ValidateUserUpdateRequest(user.UserUpdateRequest{Password: req.NewPassword}); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "validation_error", err.Error())
		return
	}

	if err := user.UpdateUser(usr.ID, user.UserUpdateRequest{Password: req.NewPassword}); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	utils.SuccessResponse(w, map[string]string{"message": "Password updated successfully"}, http.StatusOK)
}

func HandleListSessions(w http.ResponseWriter, r *http.Request) {
	usr, err := user.GetUserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	authHeader := r.Header.Get("Authorization")
	currentToken := utils.ExtractBearerToken(authHeader)

	sessions, err := session.ListSessionsByUser(usr.ID)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	var response []SessionResponse
	for _, s := range sessions {
		if s.DeactivatedAt != nil {
			continue
		}
		response = append(response, SessionResponse{
			ID:             s.ID,
			UserAgent:      s.UserAgent,
			IPAddress:      s.IPAddress,
			LastActivityAt: s.LastActivityAt,
			CreatedAt:      s.CreatedAt,
			IsCurrent:      s.AccessToken == currentToken,
		})
	}

	utils.SuccessResponse(w, response, http.StatusOK)
}

func HandleRevokeSession(w http.ResponseWriter, r *http.Request) {
	usr, err := user.GetUserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	sessionID := r.PathValue("id")
	if sessionID == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing session ID")
		return
	}

	// Fetch session to check ownership
	s, err := session.SessionByID(sessionID)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusNotFound, "not_found", "Session not found")
		return
	}

	if s.UserID != usr.ID {
		utils.WriteErrorResponse(w, http.StatusForbidden, "forbidden", "You cannot revoke someone else's session")
		return
	}

	// Check if it's the current session
	authHeader := r.Header.Get("Authorization")
	currentToken := utils.ExtractBearerToken(authHeader)
	if s.AccessToken == currentToken {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "You cannot revoke your current session from this endpoint. Use logout instead.")
		return
	}

	if err := session.DeactivateSessionByID(sessionID); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	utils.SuccessResponse(w, map[string]string{"message": "Session revoked"}, http.StatusOK)
}

func HandleListPasskeys(w http.ResponseWriter, r *http.Request) {
	usr, err := user.GetUserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	creds, err := passkey.PasskeyCredentialsByUserID(usr.ID)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	var response []PasskeyResponse
	for _, c := range creds {
		response = append(response, PasskeyResponse{
			ID:         c.ID,
			Name:       c.Name,
			CreatedAt:  c.CreatedAt,
			LastUsedAt: c.LastUsedAt,
		})
	}

	utils.SuccessResponse(w, response, http.StatusOK)
}

func HandleDeletePasskey(w http.ResponseWriter, r *http.Request) {
	usr, err := user.GetUserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	passkeyID := r.PathValue("id")
	if passkeyID == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing passkey ID")
		return
	}

	// We should check ownership but current passkey package doesn't have PasskeyByID
	// For simplicity, we just list user's passkeys and check if it's there
	creds, _ := passkey.PasskeyCredentialsByUserID(usr.ID)
	owned := false
	for _, c := range creds {
		if c.ID == passkeyID {
			owned = true
			break
		}
	}

	if !owned {
		utils.WriteErrorResponse(w, http.StatusForbidden, "forbidden", "Passkey not found or not owned by you")
		return
	}

	if err := passkey.DeletePasskeyCredential(passkeyID); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	utils.SuccessResponse(w, map[string]string{"message": "Passkey deleted"}, http.StatusOK)
}

func HandleGetMfaStatus(w http.ResponseWriter, r *http.Request) {
	usr, err := user.GetUserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	utils.SuccessResponse(w, MfaStatusResponse{
		TotpEnabled: usr.TotpVerified,
	}, http.StatusOK)
}

func HandleSetupTotp(w http.ResponseWriter, r *http.Request) {
	usr, err := user.GetUserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	secret, url, err := mfa.GenerateTotpSecret(usr.Username, config.Get().PasskeyRPName)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	// Store secret temporarily but NOT verified yet
	err = user.UpdateUser(usr.ID, user.UserUpdateRequest{
		TotpVerified: utils.Ptr(false),
	})
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	_, err = db.GetDB().Exec("UPDATE users SET totp_secret = ?, totp_verified = FALSE WHERE id = ?", secret, usr.ID)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	utils.SuccessResponse(w, TotpSetupResponse{
		Secret:     secret,
		QrCodeData: url,
	}, http.StatusOK)
}

func HandleVerifyTotp(w http.ResponseWriter, r *http.Request) {
	usr, err := user.GetUserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	var req TotpVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	// Fetch user again to get the unverified secret
	currUser, _ := user.UserByID(usr.ID)
	if currUser.TotpSecret == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "TOTP not initiated")
		return
	}

	if !mfa.ValidateTotpCode(currUser.TotpSecret, req.Code) {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_code", "Invalid TOTP code")
		return
	}

	err = user.UpdateUser(usr.ID, user.UserUpdateRequest{
		TotpVerified: utils.Ptr(true),
	})
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	utils.SuccessResponse(w, map[string]string{"message": "TOTP enabled successfully"}, http.StatusOK)
}

func HandleDeleteMfa(w http.ResponseWriter, r *http.Request) {
	usr, err := user.GetUserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	_, err = db.GetDB().Exec("UPDATE users SET totp_secret = '', totp_verified = FALSE WHERE id = ?", usr.ID)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	utils.SuccessResponse(w, map[string]string{"message": "MFA disabled"}, http.StatusOK)
}

func HandleGetSettings(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	utils.SuccessResponse(w, map[string]any{
		"auth_mode":   cfg.AuthMode,
		"mfa_enabled": cfg.MfaEnabled,
		"mfa_method":  cfg.MfaMethod,
		"oauth_path":  config.GetBootstrap().AppOAuthPath,
	}, http.StatusOK)
}
