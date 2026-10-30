package group

import (
	"fmt"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/rs/xid"
)

func CreateGroup(name, description string) (*GroupResponse, error) {
	// Group custom claims §2: all callers must preserve dot-free namespaces.
	if err := ValidateGroupCreateRequest(GroupCreateRequest{Name: name, Description: description}); err != nil {
		return nil, err
	}
	id := xid.New().String()
	var createdAt, updatedAt time.Time

	query := `INSERT INTO groups (id, name, description) VALUES (?, ?, ?) RETURNING created_at, updated_at`
	row := db.GetDB().QueryRow(query, id, name, description)
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
