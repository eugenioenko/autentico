package group

import (
	"fmt"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/rs/xid"
)

func CreateGroup(name, description string) (*GroupResponse, error) {
	id := xid.New().String()
	var createdAt, updatedAt time.Time

	query := `INSERT INTO groups (id, name, description) VALUES (?, ?, ?) RETURNING created_at, updated_at`
	row := db.GetWriteDB().QueryRow(query, id, name, description)
	if err := row.Scan(&createdAt, &updatedAt); err != nil {
		return nil, fmt.Errorf("failed to create group: %w", err)
	}

	return &GroupResponse{
		ID:          id,
		Name:        name,
		Description: description,
		CreatedAt:   createdAt,
		UpdatedAt:   updatedAt,
	}, nil
}
