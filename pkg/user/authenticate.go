package user

import (
	"database/sql"
	"fmt"

	"golang.org/x/crypto/bcrypt"

	"autentico/pkg/db"
)

// AuthenticateUser checks if the provided username and password match a user in the database.
// It returns the user details if the credentials are valid, otherwise an error.
func AuthenticateUser(username, password string) (*User, error) {
	var user User
	query := `
		SELECT id, username, password, email, created_at
		FROM users WHERE username = ?
	`
	row := db.GetDB().QueryRow(query, username)
	err := row.Scan(
		&user.ID,
		&user.Username,
		&user.Password,
		&user.Email,
		&user.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("invalid username or password")
		}
		return nil, fmt.Errorf("failed to retrieve user: %w", err)
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return nil, fmt.Errorf("invalid username or password")
	}

	return &user, nil
}
