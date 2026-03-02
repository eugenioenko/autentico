package user

import (
	"database/sql"
	"fmt"

	"github.com/eugenioenko/autentico/pkg/db"
)

func nullStringToString(ns sql.NullString) string {
	if ns.Valid {
		return ns.String
	}
	return ""
}

func ListUsers() ([]*User, error) {
	query := `
		SELECT id, username, password, email, role, created_at, failed_login_attempts, locked_until, totp_secret, totp_verified, is_email_verified, deactivated_at
		FROM users WHERE deactivated_at IS NULL
	`
	rows, err := db.GetDB().Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var users []*User
	for rows.Next() {
		var u User
		var email, password sql.NullString
		if err := rows.Scan(&u.ID, &u.Username, &password, &email, &u.Role, &u.CreatedAt, &u.FailedLoginAttempts, &u.LockedUntil, &u.TotpSecret, &u.TotpVerified, &u.IsEmailVerified, &u.DeactivatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}
		u.Password = nullStringToString(password)
		u.Email = nullStringToString(email)
		users = append(users, &u)
	}
	return users, rows.Err()
}

func UserByUsername(username string) (*User, error) {
	var user User
	var email, password sql.NullString
	query := `
		SELECT id, username, password, email, role, created_at, failed_login_attempts, locked_until, totp_secret, totp_verified, is_email_verified, deactivated_at
		FROM users WHERE username = ? AND deactivated_at IS NULL
	`
	row := db.GetDB().QueryRow(query, username)
	err := row.Scan(
		&user.ID,
		&user.Username,
		&password,
		&email,
		&user.Role,
		&user.CreatedAt,
		&user.FailedLoginAttempts,
		&user.LockedUntil,
		&user.TotpSecret,
		&user.TotpVerified,
		&user.IsEmailVerified,
		&user.DeactivatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	user.Password = nullStringToString(password)
	user.Email = nullStringToString(email)
	return &user, nil
}

func UserByID(userID string) (*User, error) {
	var user User
	var email, password sql.NullString
	query := `
		SELECT id, username, password, email, role, created_at, failed_login_attempts, locked_until, totp_secret, totp_verified, is_email_verified, deactivated_at
		FROM users WHERE id = ? AND deactivated_at IS NULL
	`
	row := db.GetDB().QueryRow(query, userID)
	err := row.Scan(
		&user.ID,
		&user.Username,
		&password,
		&email,
		&user.Role,
		&user.CreatedAt,
		&user.FailedLoginAttempts,
		&user.LockedUntil,
		&user.TotpSecret,
		&user.TotpVerified,
		&user.IsEmailVerified,
		&user.DeactivatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	user.Password = nullStringToString(password)
	user.Email = nullStringToString(email)
	return &user, nil
}

// UserByEmail returns the user with the given verified email address.
// Only returns users with is_email_verified = TRUE and no deactivated_at.
func UserByEmail(email string) (*User, error) {
	var user User
	var emailNull sql.NullString
	query := `
		SELECT id, username, password, email, role, created_at, failed_login_attempts, locked_until, totp_secret, totp_verified, is_email_verified, deactivated_at
		FROM users WHERE email = ? AND deactivated_at IS NULL AND is_email_verified = TRUE
	`
	row := db.GetDB().QueryRow(query, email)
	err := row.Scan(
		&user.ID,
		&user.Username,
		&user.Password,
		&emailNull,
		&user.Role,
		&user.CreatedAt,
		&user.FailedLoginAttempts,
		&user.LockedUntil,
		&user.TotpSecret,
		&user.TotpVerified,
		&user.IsEmailVerified,
		&user.DeactivatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}
	user.Email = nullStringToString(emailNull)
	return &user, nil
}

// CountUsers returns the total number of users in the database.
func CountUsers() (int, error) {
	var count int
	err := db.GetDB().QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count)
	return count, err
}
