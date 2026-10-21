package mfa

import (
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/totpsecret"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
)

const totpPeriod = int64(30)

// matchingTotpSteps retains the six-digit SHA-1 policy and ±1-step clock
// tolerance. All matching steps matter: a collision must not make an already
// consumed code reusable as the receiving window advances.
func matchingTotpSteps(secret, code string, now time.Time) (oldest, newest int64, found bool) {
	// RFC 6238 §3: verification requires an enrolled shared secret.
	if secret == "" {
		return 0, 0, false
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
			return 0, 0, false
		}
		if valid {
			if !found {
				newest = step
			}
			oldest, found = step, true
		}
	}
	return oldest, newest, found
}

// ConsumeTotpCode accepts an enrolled code once across all authentication paths.
// The secret comparison prevents a stale request from consuming a new enrollment.
func ConsumeTotpCode(userID, secret, code string) error {
	return consumeTotpCodeAt(userID, secret, code, time.Now())
}

func consumeTotpCodeAt(userID, secret, code string, now time.Time) error {
	oldest, newest, valid := matchingTotpSteps(secret, code, now)
	// RFC 6238 §5.2: reject invalid codes and any previously accepted timestep.
	if !valid {
		return ErrInvalidTotp
	}
	stored, err := storedTotpEnrollment(userID, secret)
	if err != nil {
		return err
	}
	result, err := db.GetDB().Exec(`UPDATE users SET totp_last_used_step = ?
		WHERE id = ? AND totp_secret = ? AND totp_verified = TRUE
		AND deactivated_at IS NULL AND totp_last_used_step < ?`, newest, userID, stored, oldest)
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

// ConfirmTotpEnrollment activates the persisted pending secret and consumes its
// code in one write. A stale browser form cannot replace newer pending setup.
func ConfirmTotpEnrollment(userID, secret, code string) error {
	oldest, newest, valid := matchingTotpSteps(secret, code, time.Now())
	// RFC 6238 §5.2: consume every matching step while activating only this enrollment.
	if !valid {
		return ErrInvalidTotp
	}
	stored, err := storedTotpEnrollment(userID, secret)
	if err != nil {
		return err
	}
	result, err := db.GetDB().Exec(`UPDATE users SET totp_verified = TRUE,
        two_factor_enabled = TRUE, totp_last_used_step = ?
        WHERE id = ? AND totp_secret = ? AND totp_verified = FALSE
        AND deactivated_at IS NULL AND totp_last_used_step < ?`, newest, userID, stored, oldest)
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

// Randomized encryption cannot be reproduced for SQL comparison. Read and
// authenticate the exact stored value, then retain it in the conditional write.
func storedTotpEnrollment(userID, proposed string) (string, error) {
	var stored string
	if err := db.GetDB().QueryRow(`SELECT totp_secret FROM users WHERE id = ?`, userID).Scan(&stored); err != nil {
		return "", err
	}
	plain, err := totpsecret.Open(config.GetBootstrap().TotpEncryptionKey, userID, stored)
	if err != nil {
		return "", err
	}
	if plain != proposed {
		return "", ErrInvalidTotp
	}
	return stored, nil
}
