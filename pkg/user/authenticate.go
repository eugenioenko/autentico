package user

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
)

// ErrAccountLocked is returned when the account is temporarily locked due to too many failed login attempts.
var ErrAccountLocked = errors.New("account is temporarily locked due to too many failed login attempts")

// AuthenticateUser checks if the provided username and password match a user in the database.
// It enforces account lockout after repeated failed attempts when configured.
func AuthenticateUser(username, password string) (*User, error) {
	var user User
	var lockedUntil *time.Time
	query := `
		SELECT id, username, password, email, created_at, role, failed_login_attempts, locked_until
		FROM users WHERE username = ?
	`
	row := db.GetDB().QueryRow(query, username)
	err := row.Scan(
		&user.ID,
		&user.Username,
		&user.Password,
		&user.Email,
		&user.CreatedAt,
		&user.Role,
		&user.FailedLoginAttempts,
		&lockedUntil,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("invalid username or password")
		}
		return nil, fmt.Errorf("failed to retrieve user: %w", err)
	}
	user.LockedUntil = lockedUntil

	maxAttempts := config.Get().AuthAccountLockoutMaxAttempts

	// Check if account is currently locked
	if maxAttempts > 0 && user.LockedUntil != nil && user.LockedUntil.After(time.Now()) {
		return nil, ErrAccountLocked
	}

	// Compare password
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		// Wrong password — increment failed attempts
		if maxAttempts > 0 {
			newAttempts := user.FailedLoginAttempts + 1
			if newAttempts >= maxAttempts {
				lockUntil := time.Now().Add(config.Get().AuthAccountLockoutDuration)
				_, _ = db.GetDB().Exec(
					`UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?`,
					newAttempts, lockUntil, user.ID,
				)
			} else {
				_, _ = db.GetDB().Exec(
					`UPDATE users SET failed_login_attempts = ? WHERE id = ?`,
					newAttempts, user.ID,
				)
			}
		}
		return nil, fmt.Errorf("invalid username or password")
	}

	// Successful login — reset failed attempts and update last_login
	if maxAttempts > 0 && user.FailedLoginAttempts > 0 {
		_, _ = db.GetDB().Exec(
			`UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login = ? WHERE id = ?`,
			time.Now(), user.ID,
		)
	} else {
		_, _ = db.GetDB().Exec(
			`UPDATE users SET last_login = ? WHERE id = ?`,
			time.Now(), user.ID,
		)
	}

	return &user, nil
}
