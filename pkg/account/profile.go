package account

import (
	"encoding/json"
	"net/http"

	"github.com/eugenioenko/autentico/pkg/config"
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

	cfg := config.Get()

	if req.Username != "" && !cfg.AllowUsernameChange {
		utils.WriteErrorResponse(w, http.StatusForbidden, "not_allowed", "Username changes are not permitted")
		return
	}

	// In is_username mode, email is derived from username — block standalone email changes
	// and sync email when username changes.
	if cfg.ProfileFieldEmail == "is_username" {
		if req.Email != "" {
			utils.WriteErrorResponse(w, http.StatusForbidden, "not_allowed", "Email cannot be changed separately when username is email")
			return
		}
		if req.Username != "" {
			req.Email = req.Username
		}
	}

	if req.Email != "" && !cfg.AllowEmailChange && cfg.ProfileFieldEmail != "is_username" {
		utils.WriteErrorResponse(w, http.StatusForbidden, "not_allowed", "Email changes are not permitted")
		return
	}

	// Check email uniqueness if changing email
	if req.Email != "" && req.Email != usr.Email {
		if user.UserExistsByEmail(req.Email) {
			utils.WriteErrorResponse(w, http.StatusConflict, "email_taken", "Email address already in use")
			return
		}
	}

	// Allow updating profile fields only — exclude password, role, totp settings
	updateReq := user.UserUpdateRequest{
		Email:             req.Email,
		Username:          req.Username,
		GivenName:         req.GivenName,
		FamilyName:        req.FamilyName,
		MiddleName:        req.MiddleName,
		Nickname:          req.Nickname,
		PhoneNumber:       req.PhoneNumber,
		Picture:           req.Picture,
		Website:           req.Website,
		Gender:            req.Gender,
		Birthdate:         req.Birthdate,
		ProfileURL:        req.ProfileURL,
		Locale:            req.Locale,
		Zoneinfo:          req.Zoneinfo,
		AddressStreet:     req.AddressStreet,
		AddressLocality:   req.AddressLocality,
		AddressRegion:     req.AddressRegion,
		AddressPostalCode: req.AddressPostalCode,
		AddressCountry:    req.AddressCountry,
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
