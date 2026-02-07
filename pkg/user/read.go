package user

import (
	"database/sql"
	"fmt"

	"github.com/eugenioenko/autentico/pkg/db"
)

func UserByID(userID string) (*User, error) {
	var user User
	query := `
		SELECT id, username, password, email, role, created_at
		FROM users WHERE id = ?
	`
	row := db.GetDB().QueryRow(query, userID)
	err := row.Scan(
		&user.ID,
		&user.Username,
		&user.Password,
		&user.Email,
		&user.Role,
		&user.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}
