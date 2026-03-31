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

// setIfNotEmpty adds the key to the map only if the value is non-empty.
// OIDC Core §5.1: claims with empty values should be omitted rather than
// returned as null, since null values may fail validation.
func setIfNotEmpty(m map[string]interface{}, key, value string) {
	if value != "" {
		m[key] = value
	}
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
	// RFC 6750 §2.1: token may arrive as Bearer Authorization header
	// RFC 6750 §2.2: or as access_token in POST application/x-www-form-urlencoded body
	var headerToken, bodyToken string
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		headerToken = utils.ExtractBearerToken(authHeader)
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err == nil {
			bodyToken = r.PostFormValue("access_token")
		}
	}
	// RFC 6750 §2.2: MUST NOT accept a request using more than one method
	realm := config.GetBootstrap().AppAuthIssuer
	if headerToken != "" && bodyToken != "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Request must not pass the access token using more than one method")
		return
	}
	accessToken := headerToken
	if accessToken == "" {
		accessToken = bodyToken
	}
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

	// OIDC Core §5.3: the sub claim MUST always be returned; it MUST match the sub in the ID token.
	scope := tok.Scope
	response := map[string]interface{}{
		"sub":   tok.UserID,
		"scope": scope,
	}

	// OIDC Core §5.4: claims are returned based on the granted scope values.
	// OIDC Core §5.1: claims with empty values are omitted rather than returned as null.
	if containsScope(scope, "profile") {
		name := user.Username
		if user.GivenName != "" || user.FamilyName != "" {
			name = strings.TrimSpace(user.GivenName + " " + user.FamilyName)
		}
		response["name"] = name
		response["preferred_username"] = user.Username
		setIfNotEmpty(response, "given_name", user.GivenName)
		setIfNotEmpty(response, "family_name", user.FamilyName)
		setIfNotEmpty(response, "middle_name", user.MiddleName)
		setIfNotEmpty(response, "nickname", user.Nickname)
		setIfNotEmpty(response, "website", user.Website)
		setIfNotEmpty(response, "gender", user.Gender)
		setIfNotEmpty(response, "birthdate", user.Birthdate)
		setIfNotEmpty(response, "profile", user.ProfileURL)
		setIfNotEmpty(response, "picture", user.Picture)
		setIfNotEmpty(response, "locale", user.Locale)
		setIfNotEmpty(response, "zoneinfo", user.Zoneinfo)
		response["updated_at"] = user.UpdatedAt.Unix()
	}

	if containsScope(scope, "email") {
		response["email"] = user.Email
		response["email_verified"] = user.IsEmailVerified
	}

	if containsScope(scope, "phone") {
		setIfNotEmpty(response, "phone_number", user.PhoneNumber)
		response["phone_number_verified"] = user.PhoneNumberVerified
	}

	if containsScope(scope, "address") {
		if user.AddressStreet != "" || user.AddressLocality != "" || user.AddressRegion != "" ||
			user.AddressPostalCode != "" || user.AddressCountry != "" {
			addr := map[string]interface{}{}
			setIfNotEmpty(addr, "street_address", user.AddressStreet)
			setIfNotEmpty(addr, "locality", user.AddressLocality)
			setIfNotEmpty(addr, "region", user.AddressRegion)
			setIfNotEmpty(addr, "postal_code", user.AddressPostalCode)
			setIfNotEmpty(addr, "country", user.AddressCountry)
			response["address"] = addr
		}
	}
	utils.WriteApiResponse(w, response, http.StatusOK)
}
