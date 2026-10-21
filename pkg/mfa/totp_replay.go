package mfa

import (
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
)

const totpPeriod = int64(30)

// matchingTotpStep retains the existing six-digit SHA-1 policy and ±1-step
// clock tolerance. Prefer the latest match if a code collides across steps so
// replaying it cannot advance through multiple matches in the same window.
func matchingTotpStep(secret, code string, now time.Time) (int64, bool) {
	// RFC 6238 §3: verification requires an enrolled shared secret.
	if secret == "" {
		return 0, false
	}
	// RFC 6238 §4.2: T is the Unix timestamp divided by the agreed step size.
	current := now.Unix() / totpPeriod
	for _, step := range []int64{current + 1, current, current - 1} {
		if step < 0 {
			continue
		}
		valid, err := hotp.ValidateCustom(code, uint64(step), secret, hotp.ValidateOpts{
			Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
		})
		if err != nil {
			return 0, false
		}
		if valid {
			return step, true
		}
	}
	return 0, false
}

// ConsumeTotpCode accepts an enrolled code once across all authentication paths.
// The secret comparison prevents a stale request from consuming a new enrollment.
func ConsumeTotpCode(userID, secret, code string) error {
	return consumeTotpCodeAt(userID, secret, code, time.Now())
}

func consumeTotpCodeAt(userID, secret, code string, now time.Time) error {
	step, valid := matchingTotpStep(secret, code, now)
	// RFC 6238 §5.2: reject invalid codes and any previously accepted timestep.
	if !valid {
		return ErrInvalidTotp
	}
	result, err := db.GetDB().Exec(`UPDATE users SET totp_last_used_step = ?
		WHERE id = ? AND totp_secret = ? AND totp_verified = TRUE
		AND deactivated_at IS NULL AND totp_last_used_step < ?`, step, userID, secret, step)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return ErrInvalidTotp
	}
	return nil
}

// ConfirmTotpEnrollment activates the expected pending enrollment and consumes
// its confirmation code in one write. Concurrent setup/confirmation cannot
// overwrite an already active or newly replaced enrollment.
func ConfirmTotpEnrollment(current user.User, secret, code string) error {
	step, valid := matchingTotpStep(secret, code, time.Now())
	// RFC 6238 §5.2: enrollment confirmation must not leave its OTP reusable.
	if !valid || current.TotpVerified {
		return ErrInvalidTotp
	}
	result, err := db.GetDB().Exec(`UPDATE users SET totp_secret = ?, totp_verified = TRUE,
		two_factor_enabled = TRUE, totp_last_used_step = ?
		WHERE id = ? AND totp_secret = ? AND totp_verified = FALSE AND deactivated_at IS NULL`,
		secret, step, current.ID, current.TotpSecret)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return ErrInvalidTotp
	}
	return nil
}
