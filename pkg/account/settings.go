package account

import (
	"net/http"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/utils"
)

func HandleGetSettings(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	utils.SuccessResponse(w, map[string]any{
		"auth_mode":                cfg.AuthMode,
		"require_mfa":              cfg.RequireMfa,
		"mfa_method":               cfg.MfaMethod,
		"oauth_path":               config.GetBootstrap().AppOAuthPath,
		"allow_username_change":     cfg.AllowUsernameChange,
		"allow_email_change":        cfg.AllowEmailChange,
		"profile_field_given_name":  cfg.ProfileFieldGivenName,
		"profile_field_family_name": cfg.ProfileFieldFamilyName,
		"profile_field_middle_name": cfg.ProfileFieldMiddleName,
		"profile_field_nickname":    cfg.ProfileFieldNickname,
		"profile_field_phone":       cfg.ProfileFieldPhone,
		"profile_field_picture":     cfg.ProfileFieldPicture,
		"profile_field_website":     cfg.ProfileFieldWebsite,
		"profile_field_gender":      cfg.ProfileFieldGender,
		"profile_field_birthdate":   cfg.ProfileFieldBirthdate,
		"profile_field_profile":     cfg.ProfileFieldProfileURL,
		"profile_field_locale":      cfg.ProfileFieldLocale,
		"profile_field_address":     cfg.ProfileFieldAddress,
	}, http.StatusOK)
}
