package auth

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	"golang.org/x/crypto/bcrypt"

	"autentico/pkg/db"

	"github.com/rs/xid"
)

// User struct for mapping database rows
type User struct {
	ID        string
	Username  string
	Password  string
	Email     string
	CreatedAt time.Time
}

func CreateUser(username, password, email string) error {
	id := xid.New()
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %v", err)
	}

	query := `INSERT INTO users (id, username, password, email) VALUES (?, ?, ?, ?)`
	_, err = db.GetDB().Exec(query, id, username, hashedPassword, email)
	if err != nil {
		return fmt.Errorf("failed to create user: %v", err)
	}

	return nil
}

func DeleteUser(id string) error {
	query := `DELETE FROM users WHERE id = ?`
	_, err := db.GetDB().Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %v", err)
	}
	return nil
}

func UpdateUser(id, newEmail string) error {
	query := `UPDATE users SET email = ? WHERE id = ?`
	_, err := db.GetDB().Exec(query, newEmail, id)
	if err != nil {
		return fmt.Errorf("failed to update user: %v", err)
	}
	return nil
}

// LoginUser checks if the username and password are correct
func LoginUser(username, password string) (*User, error) {
	var user User
	query := `SELECT id, username, password, email, created_at FROM users WHERE username = ?`
	row := db.GetDB().QueryRow(query, username)

	err := row.Scan(&user.ID, &user.Username, &user.Password, &user.Email, &user.CreatedAt)
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

	return &user, nil
}

// LogoutUser is a placeholder for session logout (no-op for stateless sessions)
func LogoutUser() {
	// This could be extended with a session or token invalidation if using session-based auth
	log.Println("User logged out (stateless)")
}
