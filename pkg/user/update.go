package user

import (
	"database/sql"
	"fmt"
	"time"

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
	newPhoneNumberVerified := usr.PhoneNumberVerified
	if req.PhoneNumberVerified != nil {
		newPhoneNumberVerified = *req.PhoneNumberVerified
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
			phone_number_verified = ?,
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
	return mutateUser(id, newRole != "admin", func(tx *sql.Tx) error {
		_, err = tx.Exec(query,
			newUsername, emailParam, newRole, newPassword, newIsEmailVerified, newTotpVerified,
			newGivenName, newFamilyName, newMiddleName, newNickname, newWebsite, newGender, newBirthdate, newProfileURL,
			newPhoneNumber, newPhoneNumberVerified, newPicture, newLocale, newZoneinfo,
			newAddressStreet, newAddressLocality, newAddressRegion, newAddressPostalCode, newAddressCountry,
			id,
		)
		if err != nil {
			return fmt.Errorf("failed to update user: %v", err)
		}
		return nil
	})
}

// DisableMfa clears the TOTP secret and marks MFA as disabled.
func DisableMfa(userID string) error {
	_, err := db.GetDB().Exec(`UPDATE users SET totp_secret = '', totp_verified = FALSE, totp_last_used_step = -1 WHERE id = ?`, userID)
	if err != nil {
		return fmt.Errorf("failed to disable MFA: %v", err)
	}
	return nil
}

// StoreTotpSecretPending stores the TOTP secret without marking it as verified.
// Interactive setup must activate through mfa.ConfirmTotpEnrollment.
func StoreTotpSecretPending(userID, secret string) error {
	return storeTotpSecret(userID, secret, false)
}

// storeTotpSecret compares the prior ciphertext so a concurrent enrollment
// cannot be overwritten. Re-saving the same plaintext keeps its replay state.
func storeTotpSecret(userID, secret string, verified bool) error {
	var prior string
	if err := db.GetDB().QueryRow(`SELECT totp_secret FROM users WHERE id = ? AND deactivated_at IS NULL`, userID).Scan(&prior); err != nil {
		return err
	}
	plain, err := decryptTotpSecret(userID, prior)
	if err != nil {
		return err
	}
	stored := prior
	if plain != secret {
		stored, err = encryptTotpSecret(userID, secret)
		if err != nil {
			return err
		}
	}
	query := `UPDATE users SET totp_last_used_step = CASE WHEN totp_secret = ? THEN totp_last_used_step ELSE -1 END,
        totp_secret = ?, totp_verified = ?, two_factor_enabled = CASE WHEN ? THEN TRUE ELSE two_factor_enabled END
		WHERE id = ? AND totp_secret = ? AND (? OR totp_verified = FALSE) AND deactivated_at IS NULL`
	result, err := db.GetDB().Exec(query, stored, stored, verified, verified, userID, prior, verified)
	if err != nil {
		return fmt.Errorf("failed to store pending TOTP secret: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return fmt.Errorf("TOTP enrollment changed or account is unavailable")
	}
	return nil
}

// EnsurePendingTotpSecret initializes browser setup without replacing a pending
// secret from a newer setup request. Active enrollment is never modified.
func EnsurePendingTotpSecret(userID, proposed string) (string, error) {
	stored, err := encryptTotpSecret(userID, proposed)
	if err != nil {
		return "", err
	}
	var secret string
	err = db.GetWriteDB().QueryRow(`UPDATE users
		SET totp_last_used_step = CASE WHEN totp_secret = '' THEN -1 ELSE totp_last_used_step END,
		totp_secret = CASE WHEN totp_secret = '' THEN ? ELSE totp_secret END
		WHERE id = ? AND totp_verified = FALSE AND deactivated_at IS NULL
		RETURNING totp_secret`, stored, userID).Scan(&secret)
	if err != nil {
		return "", err
	}
	return decryptTotpSecret(userID, secret)
}

// SaveTotpSecret stores enrollment state without validating an OTP. Interactive
// enrollment must use mfa.ConfirmTotpEnrollment to consume the confirmation code.
func SaveTotpSecret(userID, secret string) error {
	return storeTotpSecret(userID, secret, true)
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
	query := `UPDATE users SET failed_login_attempts = 0, locked_until = NULL,
		totp_failed_attempts = 0, totp_locked_until = NULL WHERE id = ?`
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

func SetEmailVerificationToken(userID, tokenHash string, expiresAt time.Time) error {
	_, err := db.GetDB().Exec(
		`UPDATE users SET email_verification_token = ?, email_verification_expires_at = ? WHERE id = ?`,
		tokenHash, expiresAt, userID,
	)
	return err
}

func MarkEmailVerified(userID string) error {
	_, err := db.GetDB().Exec(
		`UPDATE users SET is_email_verified = TRUE, email_verification_token = NULL, email_verification_expires_at = NULL WHERE id = ?`,
		userID,
	)
	return err
}
