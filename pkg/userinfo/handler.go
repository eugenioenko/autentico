package userinfo

import (
	"net/http"

	"github.com/eugenioenko/autentico/pkg/introspect"
	"github.com/eugenioenko/autentico/pkg/jwtutil"
	"github.com/eugenioenko/autentico/pkg/session"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
)

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
	if accessToken == "" {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "invalid_request", "Access token is required")
		return
	}

	// Validate the access token cryptographically
	_, err := jwtutil.ValidateAccessToken(accessToken)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "invalid_token", "Token is invalid or expired")
		return
	}

	tok, err := introspect.IntrospectToken(accessToken)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "invalid_token", "Invalid or expired token")
		return
	}

	sess, err := session.SessionByAccessToken(tok.AccessToken)
	if err != nil || sess == nil || sess.DeactivatedAt != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "invalid_grant", "Session has been deactivated")
		return
	}

	user, err := user.UserByID(tok.UserID)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Unable to fetch user information")
		return
	}

	response := map[string]interface{}{
		"sub":                tok.UserID,
		"preferred_username": user.Username,
		"email":              user.Email,
		"email_verified":     user.IsEmailVerified,
		"scope":              tok.Scope,
	}
	if user.GivenName != "" {
		response["given_name"] = user.GivenName
	}
	if user.FamilyName != "" {
		response["family_name"] = user.FamilyName
	}
	if user.GivenName != "" || user.FamilyName != "" {
		response["name"] = (user.GivenName + " " + user.FamilyName)
	}
	if user.PhoneNumber != "" {
		response["phone_number"] = user.PhoneNumber
	}
	if user.Picture != "" {
		response["picture"] = user.Picture
	}
	if user.Locale != "" {
		response["locale"] = user.Locale
	}
	if user.Zoneinfo != "" {
		response["zoneinfo"] = user.Zoneinfo
	}
	if user.AddressStreet != "" || user.AddressLocality != "" || user.AddressRegion != "" ||
		user.AddressPostalCode != "" || user.AddressCountry != "" {
		response["address"] = map[string]string{
			"street_address": user.AddressStreet,
			"locality":       user.AddressLocality,
			"region":         user.AddressRegion,
			"postal_code":    user.AddressPostalCode,
			"country":        user.AddressCountry,
		}
	}
	utils.WriteApiResponse(w, response, http.StatusOK)
}
