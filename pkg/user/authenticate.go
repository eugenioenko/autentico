package user

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
)

// ErrAccountLocked is returned when the account is temporarily locked due to too many failed login attempts.
var ErrAccountLocked = errors.New("account is temporarily locked due to too many failed login attempts")

// dummyHash is a pre-computed bcrypt hash used to burn CPU time when a
// username is not found, so the response time is indistinguishable from
// a valid-user-wrong-password attempt.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("anti-timing-dummy"), bcrypt.DefaultCost)

// verifyPasswordWithLockout checks the password against the user's stored hash
// and enforces account lockout on repeated failures. Both AuthenticateUser and
// VerifyPassword delegate to this so lockout policy is defined in one place.
func verifyPasswordWithLockout(usr *User, password string) error {
	maxAttempts := config.Get().AuthAccountLockoutMaxAttempts

	if maxAttempts > 0 && usr.LockedUntil != nil && usr.LockedUntil.After(time.Now()) {
		return ErrAccountLocked
	}

	err := bcrypt.CompareHashAndPassword([]byte(usr.Password), []byte(password))
	if err != nil {
		if maxAttempts > 0 {
			newAttempts := usr.FailedLoginAttempts + 1
			if newAttempts >= maxAttempts {
				lockUntil := time.Now().Add(config.Get().AuthAccountLockoutDuration)
				if _, dbErr := db.GetDB().Exec(
					`UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?`,
					newAttempts, lockUntil, usr.ID,
				); dbErr != nil {
					slog.Error("user: failed to lock account after max attempts", "error", dbErr, "user_id", usr.ID)
				}
			} else {
				if _, dbErr := db.GetDB().Exec(
					`UPDATE users SET failed_login_attempts = ? WHERE id = ?`,
					newAttempts, usr.ID,
				); dbErr != nil {
					slog.Error("user: failed to increment failed login attempts", "error", dbErr, "user_id", usr.ID)
				}
			}
		}
		return fmt.Errorf("invalid password")
	}

	if maxAttempts > 0 && usr.FailedLoginAttempts > 0 {
		if _, dbErr := db.GetDB().Exec(
			`UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?`,
			usr.ID,
		); dbErr != nil {
			slog.Error("user: failed to reset failed login attempts after successful login", "error", dbErr, "user_id", usr.ID)
		}
	}

	return nil
}

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
	row := db.GetDB().QueryRow(query, username)
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
			_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
			return nil, fmt.Errorf("invalid username or password")
		}
		return nil, fmt.Errorf("failed to retrieve user: %w", err)
	}
	user.LockedUntil = lockedUntil

	if user.Password == "" {
		return nil, fmt.Errorf("invalid username or password")
	}

	if err := verifyPasswordWithLockout(&user, password); err != nil {
		if errors.Is(err, ErrAccountLocked) {
			return nil, ErrAccountLocked
		}
		return nil, fmt.Errorf("invalid username or password")
	}

	if _, err := db.GetDB().Exec(
		`UPDATE users SET last_login = ? WHERE id = ?`,
		time.Now(), user.ID,
	); err != nil {
		slog.Warn("user: failed to update last_login timestamp", "error", err, "user_id", user.ID)
	}

	return &user, nil
}

// VerifyPassword checks the provided password for an already-authenticated user,
// enforcing the same lockout policy as the login flow.
func VerifyPassword(userID, password string) error {
	usr, err := UserByID(userID)
	if err != nil {
		return fmt.Errorf("invalid password")
	}

	if usr.Password == "" {
		return fmt.Errorf("invalid password")
	}

	return verifyPasswordWithLockout(usr, password)
}
