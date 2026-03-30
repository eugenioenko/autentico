package userinfo

import (
	"net/http"
	"strings"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/introspect"
	"github.com/eugenioenko/autentico/pkg/jwtutil"
	"github.com/eugenioenko/autentico/pkg/session"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
)

func nilIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func containsScope(scope, s string) bool {
	for _, part := range strings.Fields(scope) {
		if part == s {
			return true
		}
	}
	return false
}

// HandleUserInfo godoc
// @Summary Get user information
// @Description Retrieves user information based on the access token
// @Tags userinfo
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} model.ApiError
// @Failure 500 {object} model.ApiError
// @Router /oauth2/userinfo [get]
func HandleUserInfo(w http.ResponseWriter, r *http.Request) {
	// RFC 6750: token may arrive as Bearer header, or as access_token in POST body
	var accessToken string
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		accessToken = utils.ExtractBearerToken(authHeader)
	} else if r.Method == http.MethodPost {
		if err := r.ParseForm(); err == nil {
			accessToken = r.PostFormValue("access_token")
		}
	}
	realm := config.GetBootstrap().AppAuthIssuer
	if accessToken == "" {
		utils.WriteBearerUnauthorized(w, realm, "", "")
		return
	}

	// Validate the access token cryptographically
	_, err := jwtutil.ValidateAccessToken(accessToken)
	if err != nil {
		utils.WriteBearerUnauthorized(w, realm, "invalid_token", "Token is invalid or expired")
		return
	}

	tok, err := introspect.IntrospectToken(accessToken)
	if err != nil {
		utils.WriteBearerUnauthorized(w, realm, "invalid_token", "Invalid or expired token")
		return
	}

	sess, err := session.SessionByAccessToken(tok.AccessToken)
	if err != nil || sess == nil || sess.DeactivatedAt != nil {
		utils.WriteBearerUnauthorized(w, realm, "invalid_token", "Session has been deactivated")
		return
	}

	user, err := user.UserByID(tok.UserID)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Unable to fetch user information")
		return
	}

	scope := tok.Scope
	response := map[string]interface{}{
		"sub":   tok.UserID,
		"scope": scope,
	}

	if containsScope(scope, "profile") {
		name := user.Username
		if user.GivenName != "" || user.FamilyName != "" {
			name = strings.TrimSpace(user.GivenName + " " + user.FamilyName)
		}
		response["name"] = name
		response["preferred_username"] = user.Username
		response["given_name"] = nilIfEmpty(user.GivenName)
		response["family_name"] = nilIfEmpty(user.FamilyName)
		response["middle_name"] = nilIfEmpty(user.MiddleName)
		response["nickname"] = nilIfEmpty(user.Nickname)
		response["website"] = nilIfEmpty(user.Website)
		response["gender"] = nilIfEmpty(user.Gender)
		response["birthdate"] = nilIfEmpty(user.Birthdate)
		response["profile"] = nilIfEmpty(user.ProfileURL)
		response["picture"] = nilIfEmpty(user.Picture)
		response["locale"] = nilIfEmpty(user.Locale)
		response["zoneinfo"] = nilIfEmpty(user.Zoneinfo)
		response["updated_at"] = user.UpdatedAt.Unix()
	}

	if containsScope(scope, "email") {
		response["email"] = user.Email
		response["email_verified"] = user.IsEmailVerified
	}

	if containsScope(scope, "phone") {
		response["phone_number"] = nilIfEmpty(user.PhoneNumber)
		response["phone_number_verified"] = user.PhoneNumberVerified
	}

	if containsScope(scope, "address") {
		if user.AddressStreet != "" || user.AddressLocality != "" || user.AddressRegion != "" ||
			user.AddressPostalCode != "" || user.AddressCountry != "" {
			response["address"] = map[string]interface{}{
				"street_address": nilIfEmpty(user.AddressStreet),
				"locality":       nilIfEmpty(user.AddressLocality),
				"region":         nilIfEmpty(user.AddressRegion),
				"postal_code":    nilIfEmpty(user.AddressPostalCode),
				"country":        nilIfEmpty(user.AddressCountry),
			}
		} else {
			response["address"] = nil
		}
	}
	utils.WriteApiResponse(w, response, http.StatusOK)
}
