package user

import (
	"fmt"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"

	"github.com/rs/xid"
	"golang.org/x/crypto/bcrypt"
)

func CreateUser(username, password, email string) (*UserResponse, error) {
	id := xid.New().String()
	var createdAt time.Time

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		err = fmt.Errorf("failed to hash password: %w", err)
		return nil, err
	}
	hashedPasswordStr := string(hashedPassword)

	query := `INSERT INTO users (id, username, password, email) VALUES (?, ?, ?, ?) RETURNING created_at`
	row := db.GetDB().QueryRow(query, id, username, hashedPasswordStr, email)
	err = row.Scan(&createdAt)
	if err != nil {
		err = fmt.Errorf("failed to create user: %w", err)
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
