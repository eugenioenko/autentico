package user

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/verifico"
)

// ErrAccountLocked is returned when the account is temporarily locked due to too many failed login attempts.
var ErrAccountLocked = errors.New("account is temporarily locked due to too many failed login attempts")

// dummyHash is a pre-computed bcrypt hash used to burn CPU time when a
// username is not found, so the response time is indistinguishable from
// a valid-user-wrong-password attempt.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("anti-timing-dummy"), bcrypt.DefaultCost)

// AuthenticateUser checks if the provided username and password match a user in the database.
// It enforces account lockout after repeated failed attempts when configured.
func AuthenticateUser(username, password string) (*User, error) {
	var user User
	var lockedUntil *time.Time
	var email, passwordHash sql.NullString
	query := `
		SELECT id, username, password, email, created_at, role, failed_login_attempts, locked_until, totp_secret, totp_verified, is_email_verified
		FROM users WHERE username = ? AND deactivated_at IS NULL
	`
	row := db.GetReadDB().QueryRow(query, username)
	err := row.Scan(
		&user.ID,
		&user.Username,
		&passwordHash,
		&email,
		&user.CreatedAt,
		&user.Role,
		&user.FailedLoginAttempts,
		&lockedUntil,
		&user.TotpSecret,
		&user.TotpVerified,
		&user.IsEmailVerified,
	)
	user.Password = nullStringToString(passwordHash)
	user.Email = nullStringToString(email)
	if err != nil {
		if err == sql.ErrNoRows {
			// Burn CPU time so response is indistinguishable from wrong-password
			_ = verifico.CompareHashAndPassword(dummyHash, []byte(password))
			return nil, fmt.Errorf("invalid username or password")
		}
		return nil, fmt.Errorf("failed to retrieve user: %w", err)
	}
	user.LockedUntil = lockedUntil

	// Passkey-only users have no password; reject password login attempts.
	if user.Password == "" {
		return nil, fmt.Errorf("invalid username or password")
	}

	maxAttempts := config.Get().AuthAccountLockoutMaxAttempts

	// Check if account is currently locked
	if maxAttempts > 0 && user.LockedUntil != nil && user.LockedUntil.After(time.Now()) {
		return nil, ErrAccountLocked
	}

	// Compare password
	err = verifico.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		// Wrong password — increment failed attempts
		if maxAttempts > 0 {
			newAttempts := user.FailedLoginAttempts + 1
			if newAttempts >= maxAttempts {
				lockUntil := time.Now().Add(config.Get().AuthAccountLockoutDuration)
				_, _ = db.GetWriteDB().Exec(
					`UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?`,
					newAttempts, lockUntil, user.ID,
				)
			} else {
				_, _ = db.GetWriteDB().Exec(
					`UPDATE users SET failed_login_attempts = ? WHERE id = ?`,
					newAttempts, user.ID,
				)
			}
		}
		return nil, fmt.Errorf("invalid username or password")
	}

	// Successful login — reset failed attempts and update last_login
	if maxAttempts > 0 && user.FailedLoginAttempts > 0 {
		_, _ = db.GetWriteDB().Exec(
			`UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login = ? WHERE id = ?`,
			time.Now(), user.ID,
		)
	} else {
		_, _ = db.GetWriteDB().Exec(
			`UPDATE users SET last_login = ? WHERE id = ?`,
			time.Now(), user.ID,
		)
	}

	return &user, nil
}
