package group

import (
	"fmt"

	"github.com/eugenioenko/autentico/pkg/db"
)

// UpdateGroup validates proposed changes before loading or modifying a group.
// Empty fields retain their current values; invalid input leaves the group unchanged.
func UpdateGroup(id string, req GroupUpdateRequest) error {
	// Group custom claims §2: renames must preserve dot-free claim namespaces.
	if err := ValidateGroupUpdateRequest(req); err != nil {
		return err
	}
	g, err := GroupByID(id)
	if err != nil {
		return err
	}

	name := g.Name
	description := g.Description

	if req.Name != "" {
		name = req.Name
	}
	if req.Description != "" {
		description = req.Description
	}

	query := `UPDATE groups SET name = ?, description = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`
	_, err = db.GetDB().Exec(query, name, description, id)
	if err != nil {
		return fmt.Errorf("failed to update group: %w", err)
	}
	return nil
}
