package auth

import (
	"database/sql"
	"fmt"

	"golang.org/x/crypto/bcrypt"

	"autentico/pkg/db"
	. "autentico/pkg/models"
)

func LoginUser(username, password string) (*AuthUser, error) {
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
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %v", err)
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return nil, fmt.Errorf("invalid password: %v", err)
	}

	accessToken, _, err := GenerateTokens(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %v", err)
	}

	authUser := &AuthUser{
		ID:    user.ID,
		Token: accessToken,
	}

	return authUser, nil
}
