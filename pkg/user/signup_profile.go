package user

import (
	"errors"
	"net/url"

	"github.com/eugenioenko/autentico/pkg/config"
)

func SignupProfile(values url.Values, cfg *config.Config) (UserUpdateRequest, error) {
	// Validate required profile fields
	profileFields := map[string]string{
		"given_name":          values.Get("given_name"),
		"family_name":         values.Get("family_name"),
		"phone_number":        values.Get("phone_number"),
		"picture":             values.Get("picture"),
		"locale":              values.Get("locale"),
		"address_street":      values.Get("address_street"),
		"address_locality":    values.Get("address_locality"),
		"address_region":      values.Get("address_region"),
		"address_postal_code": values.Get("address_postal_code"),
		"address_country":     values.Get("address_country"),
	}
	fieldVisibility := map[string]string{
		"given_name":          cfg.ProfileFieldGivenName,
		"family_name":         cfg.ProfileFieldFamilyName,
		"phone_number":        cfg.ProfileFieldPhone,
		"picture":             cfg.ProfileFieldPicture,
		"locale":              cfg.ProfileFieldLocale,
		"address_street":      cfg.ProfileFieldAddress,
		"address_locality":    cfg.ProfileFieldAddress,
		"address_region":      cfg.ProfileFieldAddress,
		"address_postal_code": cfg.ProfileFieldAddress,
		"address_country":     cfg.ProfileFieldAddress,
	}
	for field, visibility := range fieldVisibility {
		if visibility == "required" && profileFields[field] == "" {
			return UserUpdateRequest{}, errors.New("Please fill in all required fields") //nolint:staticcheck // Displayed verbatim on the signup form.
		}
	}

	// Validate profile fields (e.g. URL scheme checks) before creating the user
	profileUpdate := UserUpdateRequest{
		GivenName:         profileFields["given_name"],
		FamilyName:        profileFields["family_name"],
		PhoneNumber:       profileFields["phone_number"],
		Picture:           profileFields["picture"],
		Locale:            profileFields["locale"],
		AddressStreet:     profileFields["address_street"],
		AddressLocality:   profileFields["address_locality"],
		AddressRegion:     profileFields["address_region"],
		AddressPostalCode: profileFields["address_postal_code"],
		AddressCountry:    profileFields["address_country"],
	}
	if err := ValidateUserUpdateRequest(profileUpdate); err != nil {
		return UserUpdateRequest{}, err
	}

	return profileUpdate, nil
}
