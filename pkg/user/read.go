package user

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/eugenioenko/autentico/pkg/api"
	"github.com/eugenioenko/autentico/pkg/db"
)

var userListConfig = api.ListConfig{
	AllowedSort: map[string]bool{
		"username": true, "email": true, "id": true,
		"given_name": true, "family_name": true, "middle_name": true,
		"nickname": true, "phone_number": true,
		"created_at": true, "updated_at": true, "role": true,
	},
	SearchColumns: []string{
		"username", "email", "id",
		"given_name", "family_name", "middle_name",
		"nickname", "phone_number",
	},
	AllowedFilters: map[string]bool{
		"role": true, "is_email_verified": true, "totp_verified": true,
	},
	DefaultSort: "created_at",
	MaxLimit:    api.DefaultMaxLimit,
	TableAlias:  "users",
}

func nullStringToString(ns sql.NullString) string {
	if ns.Valid {
		return ns.String
	}
	return ""
}

const userSelectColumns = `
	users.id, users.username, users.password, users.email, users.role, users.created_at, users.updated_at, users.failed_login_attempts, users.locked_until,
	users.totp_secret, users.totp_verified, users.is_email_verified, users.deactivated_at, users.registered_at,
	users.given_name, users.family_name, users.middle_name, users.nickname, users.website, users.gender, users.birthdate, users.profile,
	users.phone_number, users.phone_number_verified, users.picture, users.locale, users.zoneinfo,
	users.address_street, users.address_locality, users.address_region, users.address_postal_code, users.address_country
`

func scanUser(row interface {
	Scan(dest ...any) error
}) (*User, error) {
	var u User
	var email, password sql.NullString
	err := row.Scan(
		&u.ID, &u.Username, &password, &email, &u.Role, &u.CreatedAt, &u.UpdatedAt,
		&u.FailedLoginAttempts, &u.LockedUntil, &u.TotpSecret, &u.TotpVerified,
		&u.IsEmailVerified, &u.DeactivatedAt, &u.RegisteredAt,
		&u.GivenName, &u.FamilyName, &u.MiddleName, &u.Nickname, &u.Website, &u.Gender, &u.Birthdate, &u.ProfileURL,
		&u.PhoneNumber, &u.PhoneNumberVerified, &u.Picture, &u.Locale, &u.Zoneinfo,
		&u.AddressStreet, &u.AddressLocality, &u.AddressRegion, &u.AddressPostalCode, &u.AddressCountry,
	)
	if err != nil {
		return nil, err
	}
	u.Password = nullStringToString(password)
	u.Email = nullStringToString(email)
	return &u, nil
}

func ListUsers() ([]*User, error) {
	query := `SELECT` + userSelectColumns + `FROM users WHERE deactivated_at IS NULL`
	rows, err := db.GetDB().Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var users []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func ListUsersWithParams(params api.ListParams, dateWhere string, dateArgs []any) ([]*User, int, error) {
	lq := api.BuildListQuery(params, userListConfig)

	baseWhere := "WHERE users.deactivated_at IS NULL"
	join := ""
	var extraArgs []any

	if groupName, ok := params.Filters["group"]; ok {
		join = " JOIN user_groups ug ON users.id = ug.user_id JOIN groups g ON ug.group_id = g.id"
		baseWhere += " AND g.name = ?"
		extraArgs = append(extraArgs, groupName)
		delete(params.Filters, "group")
	}

	allArgs := append(dateArgs, extraArgs...)
	allArgs = append(allArgs, lq.Args...)

	var total int
	countQuery := "SELECT COUNT(*) FROM users" + join + " " + baseWhere + dateWhere + lq.Where
	if err := db.GetDB().QueryRow(countQuery, allArgs...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count users: %w", err)
	}

	query := `SELECT` + userSelectColumns + `FROM users` + join + ` ` + baseWhere + dateWhere + lq.Where + lq.Order
	rows, err := db.GetDB().Query(query, allArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list users: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var users []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan user: %w", err)
		}
		users = append(users, u)
	}
	return users, total, rows.Err()
}

func UserByUsername(username string) (*User, error) {
	query := `SELECT` + userSelectColumns + `FROM users WHERE username = ? AND deactivated_at IS NULL`
	row := db.GetDB().QueryRow(query, username)
	u, err := scanUser(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return u, nil
}

func UserByID(userID string) (*User, error) {
	query := `SELECT` + userSelectColumns + `FROM users WHERE id = ? AND deactivated_at IS NULL`
	row := db.GetDB().QueryRow(query, userID)
	u, err := scanUser(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return u, nil
}

// UserByEmail returns the user with the given verified email address.
// Only returns users with is_email_verified = TRUE and no deactivated_at.
func UserByEmail(email string) (*User, error) {
	query := `SELECT` + userSelectColumns + `FROM users WHERE email = ? AND deactivated_at IS NULL AND is_email_verified = TRUE`
	row := db.GetDB().QueryRow(query, strings.ToLower(email))
	u, err := scanUser(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}
	return u, nil
}

// GetVerificationTokenInfo returns the userID and expiry for a given token hash.
// Returns sql.ErrNoRows if the token does not exist.
func GetVerificationTokenInfo(tokenHash string) (userID string, expiresAt time.Time, err error) {
	err = db.GetDB().QueryRow(
		`SELECT id, email_verification_expires_at FROM users WHERE email_verification_token = ? AND deactivated_at IS NULL`,
		tokenHash,
	).Scan(&userID, &expiresAt)
	return
}

// UserExistsByEmail returns true if any non-deactivated user has the given email,
// regardless of email verification status. Used to prevent duplicate email assignment.
func UserExistsByEmail(email string) bool {
	var count int
	_ = db.GetDB().QueryRow(`SELECT COUNT(*) FROM users WHERE email = ? AND deactivated_at IS NULL`, strings.ToLower(email)).Scan(&count)
	return count > 0
}

// UserByIDIncludingDeactivated returns a user by ID without filtering by deactivated_at.
// Used by introspection and admin operations that need to check deactivated users.
func UserByIDIncludingDeactivated(userID string) (*User, error) {
	query := `SELECT` + userSelectColumns + `FROM users WHERE id = ?`
	row := db.GetDB().QueryRow(query, userID)
	u, err := scanUser(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return u, nil
}

// CountUsers returns the total number of users in the database.
func CountUsers() (int, error) {
	var count int
	err := db.GetDB().QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count)
	return count, err
}
