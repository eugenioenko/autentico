package user

import (
	"fmt"

	"github.com/eugenioenko/autentico/pkg/db"
	"golang.org/x/crypto/bcrypt"
)

func UpdateUser(id string, req UserUpdateRequest) error {
	// Get existing user to preserve values
	usr, err := UserByID(id)
	if err != nil {
		return err
	}

	newUsername := usr.Username
	if req.Username != "" {
		newUsername = req.Username
	}

	newEmail := usr.Email
	if req.Email != "" {
		newEmail = req.Email
	}

	newRole := usr.Role
	if req.Role != "" {
		newRole = req.Role
	}

	newPassword := usr.Password
	if req.Password != "" {
		hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("failed to hash password: %w", err)
		}
		newPassword = string(hashed)
	}

	newIsEmailVerified := usr.IsEmailVerified
	if req.IsEmailVerified != nil {
		newIsEmailVerified = *req.IsEmailVerified
	}

	newTotpVerified := usr.TotpVerified
	if req.TotpVerified != nil {
		newTotpVerified = *req.TotpVerified
	}

	newGivenName := usr.GivenName
	if req.GivenName != "" {
		newGivenName = req.GivenName
	}
	newFamilyName := usr.FamilyName
	if req.FamilyName != "" {
		newFamilyName = req.FamilyName
	}
	newMiddleName := usr.MiddleName
	if req.MiddleName != "" {
		newMiddleName = req.MiddleName
	}
	newNickname := usr.Nickname
	if req.Nickname != "" {
		newNickname = req.Nickname
	}
	newWebsite := usr.Website
	if req.Website != "" {
		newWebsite = req.Website
	}
	newGender := usr.Gender
	if req.Gender != "" {
		newGender = req.Gender
	}
	newBirthdate := usr.Birthdate
	if req.Birthdate != "" {
		newBirthdate = req.Birthdate
	}
	newProfileURL := usr.ProfileURL
	if req.ProfileURL != "" {
		newProfileURL = req.ProfileURL
	}
	newPhoneNumber := usr.PhoneNumber
	if req.PhoneNumber != "" {
		newPhoneNumber = req.PhoneNumber
	}
	newPicture := usr.Picture
	if req.Picture != "" {
		newPicture = req.Picture
	}
	newLocale := usr.Locale
	if req.Locale != "" {
		newLocale = req.Locale
	}
	newZoneinfo := usr.Zoneinfo
	if req.Zoneinfo != "" {
		newZoneinfo = req.Zoneinfo
	}
	newAddressStreet := usr.AddressStreet
	if req.AddressStreet != "" {
		newAddressStreet = req.AddressStreet
	}
	newAddressLocality := usr.AddressLocality
	if req.AddressLocality != "" {
		newAddressLocality = req.AddressLocality
	}
	newAddressRegion := usr.AddressRegion
	if req.AddressRegion != "" {
		newAddressRegion = req.AddressRegion
	}
	newAddressPostalCode := usr.AddressPostalCode
	if req.AddressPostalCode != "" {
		newAddressPostalCode = req.AddressPostalCode
	}
	newAddressCountry := usr.AddressCountry
	if req.AddressCountry != "" {
		newAddressCountry = req.AddressCountry
	}

	var emailParam interface{}
	if newEmail != "" {
		emailParam = newEmail
	}
	query := `
		UPDATE users SET
			username = ?,
			email = ?,
			role = ?,
			password = ?,
			is_email_verified = ?,
			totp_verified = ?,
			given_name = ?,
			family_name = ?,
			middle_name = ?,
			nickname = ?,
			website = ?,
			gender = ?,
			birthdate = ?,
			profile = ?,
			phone_number = ?,
			picture = ?,
			locale = ?,
			zoneinfo = ?,
			address_street = ?,
			address_locality = ?,
			address_region = ?,
			address_postal_code = ?,
			address_country = ?,
			updated_at = CURRENT_TIMESTAMP
		WHERE id = ?`
	_, err = db.GetDB().Exec(query,
		newUsername, emailParam, newRole, newPassword, newIsEmailVerified, newTotpVerified,
		newGivenName, newFamilyName, newMiddleName, newNickname, newWebsite, newGender, newBirthdate, newProfileURL,
		newPhoneNumber, newPicture, newLocale, newZoneinfo,
		newAddressStreet, newAddressLocality, newAddressRegion, newAddressPostalCode, newAddressCountry,
		id,
	)
	if err != nil {
		return fmt.Errorf("failed to update user: %v", err)
	}
	return nil
}

// DisableMfa clears the TOTP secret and marks MFA as disabled.
func DisableMfa(userID string) error {
	_, err := db.GetDB().Exec(`UPDATE users SET totp_secret = '', totp_verified = FALSE WHERE id = ?`, userID)
	if err != nil {
		return fmt.Errorf("failed to disable MFA: %v", err)
	}
	return nil
}

// StoreTotpSecretPending stores the TOTP secret without marking it as verified.
// Used during the setup flow — call SaveTotpSecret after the user confirms the code.
func StoreTotpSecretPending(userID, secret string) error {
	query := `UPDATE users SET totp_secret = ?, totp_verified = FALSE WHERE id = ?`
	_, err := db.GetDB().Exec(query, secret, userID)
	if err != nil {
		return fmt.Errorf("failed to store pending TOTP secret: %v", err)
	}
	return nil
}

func SaveTotpSecret(userID, secret string) error {
	query := `UPDATE users SET totp_secret = ?, totp_verified = TRUE, two_factor_enabled = TRUE WHERE id = ?`
	_, err := db.GetDB().Exec(query, secret, userID)
	if err != nil {
		return fmt.Errorf("failed to save TOTP secret: %v", err)
	}
	return nil
}

// SetRegisteredAt marks the user's registration as complete by stamping registered_at.
func SetRegisteredAt(id string) error {
	_, err := db.GetDB().Exec(`UPDATE users SET registered_at = CURRENT_TIMESTAMP WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("failed to set registered_at: %w", err)
	}
	return nil
}

func UnlockUser(id string) error {
	query := `UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?`
	result, err := db.GetDB().Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to unlock user: %v", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to unlock user: %v", err)
	}
	if rows == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}
