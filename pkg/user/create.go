package user

import (
	"fmt"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"

	"github.com/rs/xid"
	"golang.org/x/crypto/bcrypt"
)

// CreatePasskeyUser creates a user with a NULL password for passkey-only authentication.
func CreatePasskeyUser(username, email string) (*UserResponse, error) {
	id := xid.New().String()
	var createdAt time.Time

	var emailParam any
	if email != "" {
		emailParam = email
	}
	query := `INSERT INTO users (id, username, email) VALUES (?, ?, ?) RETURNING created_at`
	row := db.GetDB().QueryRow(query, id, username, emailParam)
	if err := row.Scan(&createdAt); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return &UserResponse{
		ID:        id,
		Username:  username,
		Email:     email,
		CreatedAt: createdAt,
		Role:      "user",
	}, nil
}

func CreateUser(username, password, email string) (*UserResponse, error) {
	id := xid.New().String()
	var createdAt time.Time

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		err = fmt.Errorf("failed to hash password: %w", err)
		return nil, err
	}
	hashedPasswordStr := string(hashedPassword)

	var emailParam any
	if email != "" {
		emailParam = email
	}
	query := `INSERT INTO users (id, username, password, email) VALUES (?, ?, ?, ?) RETURNING created_at`
	row := db.GetDB().QueryRow(query, id, username, hashedPasswordStr, emailParam)
	err = row.Scan(&createdAt)
	if err != nil {
		err = fmt.Errorf("failed to create user: %w", err)
		return nil, err
	}

	user := &UserResponse{
		ID:              id,
		Username:        username,
		Email:           email,
		CreatedAt:       createdAt,
		Role:            "user", // default role
		IsEmailVerified: false,
		TotpVerified:    false,
	}

	return user, nil
}
