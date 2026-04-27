package group

import (
	"fmt"

	"github.com/eugenioenko/autentico/pkg/db"
)

func UpdateGroup(id string, req GroupUpdateRequest) error {
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
