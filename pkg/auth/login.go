package auth

import (
	"database/sql"
	"fmt"

	"golang.org/x/crypto/bcrypt"

	"autentico/pkg/db"
	. "autentico/pkg/models"
)

func LoginUser(username, password string) (*AuthToken, error) {
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
			return nil, fmt.Errorf("User not found")
		}
		return nil, fmt.Errorf("Failed to get user: %w", err)
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return nil, fmt.Errorf("Invalid password: %w", err)
	}

	tokens, err := GenerateTokens(user)
	if err != nil {
		return nil, fmt.Errorf("Failed to generate tokens: %w", err)
	}

	return tokens, nil
}
