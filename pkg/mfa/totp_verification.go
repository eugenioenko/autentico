package mfa

import (
	"context"
	"database/sql/driver"
	"errors"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/totpsecret"
)

var (
	ErrInvalidTotp = errors.New("invalid TOTP code")
	ErrTotpLocked  = errors.New("too many failed TOTP attempts; try again later")
)

const maxTotpAttempts = 5

// VerifyEnrolledTotp enforces a persistent account-level TOTP attempt budget.
// Password checks and source IPs do not reset it. Five failures lock verification
// for account_lockout_duration (15 minutes when that duration is nonpositive).
func VerifyEnrolledTotp(userID, code string) error {
	return verifyEnrolledTotpAt(userID, code, time.Now())
}

// VerifyPasswordGrantTotp retains the password-grant API with the shared budget.
func VerifyPasswordGrantTotp(userID, code string) error {
	return VerifyEnrolledTotp(userID, code)
}

func verifyEnrolledTotpAt(userID, code string, now time.Time) error {
	ctx := context.Background()
	conn, err := db.GetWriteDB().Conn(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var secret string
	var verified bool
	var attempts int
	var lastUsedStep int64
	var lockedUntil *time.Time
	err = tx.QueryRow(`SELECT totp_secret, totp_verified, totp_failed_attempts, totp_locked_until, totp_last_used_step
		FROM users WHERE id = ? AND deactivated_at IS NULL`, userID).Scan(&secret, &verified, &attempts, &lockedUntil, &lastUsedStep)
	if err != nil {
		return err
	}
	secret, err = totpsecret.Open(config.GetBootstrap().TotpEncryptionKey, userID, secret)
	if err != nil {
		return err
	}
	if lockedUntil != nil {
		if now.Before(*lockedUntil) {
			return ErrTotpLocked
		}
		attempts = 0
		lockedUntil = nil
	}

	var verificationErr error
	oldest, newest, valid := matchingTotpSteps(secret, code, now)
	// RFC 4226 §7.3 / RFC 6238 §5.2: share the attempt budget and replay
	// watermark across browser login, password grant and TOTP removal.
	if !verified || !valid || oldest <= lastUsedStep {
		attempts++
		verificationErr = ErrInvalidTotp
		if attempts >= maxTotpAttempts {
			duration := config.Get().AuthAccountLockoutDuration
			if duration <= 0 {
				duration = 15 * time.Minute
			}
			until := now.Add(duration)
			lockedUntil = &until
			verificationErr = ErrTotpLocked
		}
	} else {
		attempts = 0
		lastUsedStep = newest
	}
	if _, err := tx.Exec(`UPDATE users SET totp_failed_attempts = ?, totp_locked_until = ?, totp_last_used_step = ? WHERE id = ?`,
		attempts, lockedUntil, lastUsedStep, userID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		if _, rollbackErr := conn.ExecContext(ctx, "ROLLBACK"); rollbackErr != nil {
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
			err = errors.Join(err, rollbackErr)
		}
		return err
	}
	return verificationErr
}
