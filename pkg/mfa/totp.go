package mfa

import (
	"github.com/pquerna/otp/totp"
)

func GenerateTotpSecret(username, issuer string) (secret string, otpauthURL string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: username,
	})
	if err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}

// ValidateTotpCode checks only the code and time window, without replay state.
// Authentication must use ConsumeTotpCode or VerifyPasswordGrantTotp instead.
func ValidateTotpCode(secret, code string) bool {
	return totp.Validate(code, secret)
}
