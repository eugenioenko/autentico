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
	cfg := config.Get()
	if cfg.AuthAccountLockoutMaxAttempts > 0 && usr.LockedUntil != nil && usr.LockedUntil.After(time.Now()) {
		return ErrAccountLocked
	}
	// OWASP Authentication §Account Lockout: compute bcrypt outside the writer,
	// then check current credentials/lockout and account every failed attempt atomically.
	matches := bcrypt.CompareHashAndPassword([]byte(usr.Password), []byte(password)) == nil
	var authenticationErr error
	err := mutateUser(usr.ID, false, func(tx *sql.Tx) error {
		var hash sql.NullString
		var failed int
		var locked sql.NullTime
		err := tx.QueryRow(`SELECT password,failed_login_attempts,locked_until FROM users WHERE id=? AND deactivated_at IS NULL`, usr.ID).Scan(&hash, &failed, &locked)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && hash.String != usr.Password) {
			authenticationErr = fmt.Errorf("invalid password")
			return nil
		}
		if err != nil {
			return err
		}
		if cfg.AuthAccountLockoutMaxAttempts > 0 && locked.Valid && locked.Time.After(time.Now()) {
			authenticationErr = ErrAccountLocked
			return nil
		}
		if !matches {
			authenticationErr = fmt.Errorf("invalid password")
			if cfg.AuthAccountLockoutMaxAttempts > 0 {
				var until any
				if failed+1 >= cfg.AuthAccountLockoutMaxAttempts {
					until = time.Now().Add(cfg.AuthAccountLockoutDuration)
				}
				_, err = tx.Exec(`UPDATE users SET failed_login_attempts=failed_login_attempts+1,locked_until=? WHERE id=?`, until, usr.ID)
			}
			return err
		}
		if cfg.AuthAccountLockoutMaxAttempts > 0 && (failed > 0 || locked.Valid) {
			_, err = tx.Exec(`UPDATE users SET failed_login_attempts=0,locked_until=NULL WHERE id=?`, usr.ID)
		}
		return err
	})
	if err != nil {
		return err
	}
	return authenticationErr
}

// PasswordConfirmation is an opaque snapshot of successfully verified credentials.
// Destructive operations must check it again under their mutation's writer lock.
type PasswordConfirmation struct{ userID, passwordHash string }

// ConfirmPassword verifies current credentials and returns a transaction-checkable snapshot.
func ConfirmPassword(userID, password string) (PasswordConfirmation, error) {
	usr, err := UserByID(userID)
	if err != nil || usr.Password == "" {
		return PasswordConfirmation{}, fmt.Errorf("invalid password")
	}
	if err := verifyPasswordWithLockout(usr, password); err != nil {
		return PasswordConfirmation{}, err
	}
	return PasswordConfirmation{userID: usr.ID, passwordHash: usr.Password}, nil
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
	user.TotpSecret, err = decryptTotpSecret(user.ID, user.TotpSecret)
	if err != nil {
		return nil, err
	}

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
	_, err := ConfirmPassword(userID, password)
	return err
}
