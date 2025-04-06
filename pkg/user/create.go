package user

import (
	"autentico/pkg/db"
	. "autentico/pkg/model"
	"fmt"
	"time"

	"github.com/rs/xid"
	"golang.org/x/crypto/bcrypt"
)

func CreateUser(username, password, email string) (*UserResponse, error) {
	id := xid.New().String()
	var createdAt time.Time

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		err = fmt.Errorf("Failed to hash password: %w", err)
		return nil, err
	}
	hashedPasswordStr := string(hashedPassword)

	query := `INSERT INTO users (id, username, password, email) VALUES (?, ?, ?, ?) RETURNING created_at`
	err = db.GetDB().QueryRow(query, id, username, hashedPasswordStr, email).Scan(&createdAt)
	if err != nil {
		err = fmt.Errorf("Failed to create user: %w", err)
		return nil, err
	}

	user := &UserResponse{
		ID:        id,
		Username:  username,
		Email:     email,
		CreatedAt: createdAt,
	}

	return user, nil
}
