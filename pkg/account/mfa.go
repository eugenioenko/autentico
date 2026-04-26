package account

import (
	"encoding/json"
	"net/http"

	"github.com/eugenioenko/autentico/pkg/audit"
	"github.com/eugenioenko/autentico/pkg/bearer"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/mfa"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
	"github.com/eugenioenko/autentico/pkg/verifico"
)

// HandleGetMfaStatus godoc
// @Summary Get MFA status
// @Description Returns the MFA enrollment status for the authenticated user.
// @Tags account-security
// @Produce json
// @Security UserAuth
// @Success 200 {object} MfaStatusResponse
// @Failure 401 {object} model.ApiError
// @Router /account/api/mfa [get]
func HandleGetMfaStatus(w http.ResponseWriter, r *http.Request) {
	usr, err := bearer.UserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	utils.SuccessResponse(w, MfaStatusResponse{
		TotpEnabled: usr.TotpVerified,
	}, http.StatusOK)
}

// HandleSetupTotp godoc
// @Summary Begin TOTP setup
// @Description Generates a TOTP secret and QR code URI for enrollment. Must be verified before activation.
// @Tags account-security
// @Produce json
// @Security UserAuth
// @Success 200 {object} TotpSetupResponse
// @Failure 401 {object} model.ApiError
// @Failure 409 {object} model.ApiError
// @Router /account/api/mfa/totp/setup [post]
func HandleSetupTotp(w http.ResponseWriter, r *http.Request) {
	usr, err := bearer.UserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	// Block re-enrollment if TOTP is already verified — must disable first.
	if usr.TotpVerified {
		utils.WriteErrorResponse(w, http.StatusConflict, "already_enrolled", "TOTP is already enrolled. Disable it first before re-enrolling.")
		return
	}

	secret, url, err := mfa.GenerateTotpSecret(usr.Username, config.Get().PasskeyRPName)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	if err := user.StoreTotpSecretPending(usr.ID, secret); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	utils.SuccessResponse(w, TotpSetupResponse{
		Secret:     secret,
		QrCodeData: url,
	}, http.StatusOK)
}

// HandleVerifyTotp godoc
// @Summary Verify TOTP enrollment
// @Description Verifies a TOTP code to complete enrollment. The secret must have been generated via setup first.
// @Tags account-security
// @Accept json
// @Produce json
// @Param request body TotpVerifyRequest true "TOTP verification code"
// @Security UserAuth
// @Success 200 {object} map[string]string
// @Failure 400 {object} model.ApiError
// @Failure 401 {object} model.ApiError
// @Router /account/api/mfa/totp/verify [post]
func HandleVerifyTotp(w http.ResponseWriter, r *http.Request) {
	usr, err := bearer.UserFromRequest(r)
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

	if err := user.SaveTotpSecret(usr.ID, currUser.TotpSecret); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	audit.Log(audit.EventMfaEnrolled, usr, audit.TargetUser, usr.ID, audit.Detail("method", "totp", "source", "account"), utils.GetClientIP(r))
	utils.SuccessResponse(w, map[string]string{"message": "TOTP enabled successfully"}, http.StatusOK)
}

// HandleDeleteMfa godoc
// @Summary Disable MFA
// @Description Disables TOTP MFA for the authenticated user. Requires current password and a valid TOTP code. Revokes all sessions after disabling.
// @Tags account-security
// @Accept json
// @Produce json
// @Param request body DisableMfaRequest true "Password and TOTP code for confirmation"
// @Security UserAuth
// @Success 200 {object} map[string]string
// @Failure 400 {object} model.ApiError
// @Failure 401 {object} model.ApiError
// @Failure 403 {object} model.ApiError
// @Router /account/api/mfa/totp [delete]
func HandleDeleteMfa(w http.ResponseWriter, r *http.Request) {
	usr, err := bearer.UserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	var req DisableMfaRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	// Require password confirmation if the user has a password
	if usr.Password != "" {
		if err := verifico.CompareHashAndPassword([]byte(usr.Password), []byte(req.CurrentPassword)); err != nil {
			utils.WriteErrorResponse(w, http.StatusForbidden, "invalid_password", "Current password does not match")
			return
		}
	}

	// Require a valid TOTP code to prove possession of the enrolled device.
	if usr.TotpSecret == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "TOTP is not enrolled")
		return
	}
	if req.Code == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "TOTP code is required to disable MFA")
		return
	}
	if !mfa.ValidateTotpCode(usr.TotpSecret, req.Code) {
		utils.WriteErrorResponse(w, http.StatusForbidden, "invalid_code", "Invalid TOTP code")
		return
	}

	if err := user.DisableMfa(usr.ID); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	// Invalidate all sessions/tokens after MFA is disabled so that
	// any compromised session cannot persist silently.
	_ = user.RevokeAllUserAccess(usr.ID)

	audit.Log(audit.EventMfaDisabled, usr, audit.TargetUser, usr.ID, nil, utils.GetClientIP(r))
	utils.SuccessResponse(w, map[string]string{"message": "MFA disabled"}, http.StatusOK)
}
