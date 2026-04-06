package group

import (
	"database/sql"
	"fmt"

	"github.com/eugenioenko/autentico/pkg/db"
)

func ListGroups() ([]GroupResponse, error) {
	query := `SELECT id, name, description, created_at, updated_at FROM groups ORDER BY name`
	rows, err := db.GetDB().Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to list groups: %w", err)
	}
	defer rows.Close()

	var groups []GroupResponse
	for rows.Next() {
		var g GroupResponse
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.CreatedAt, &g.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan group: %w", err)
		}
		groups = append(groups, g)
	}
	if groups == nil {
		groups = []GroupResponse{}
	}
	return groups, nil
}

func GroupByID(id string) (*Group, error) {
	query := `SELECT id, name, description, created_at, updated_at FROM groups WHERE id = ?`
	var g Group
	err := db.GetDB().QueryRow(query, id).Scan(&g.ID, &g.Name, &g.Description, &g.CreatedAt, &g.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("group not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get group: %w", err)
	}
	return &g, nil
}

func GroupByName(name string) (*Group, error) {
	query := `SELECT id, name, description, created_at, updated_at FROM groups WHERE name = ?`
	var g Group
	err := db.GetDB().QueryRow(query, name).Scan(&g.ID, &g.Name, &g.Description, &g.CreatedAt, &g.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("group not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get group: %w", err)
	}
	return &g, nil
}

func GroupsByUserID(userID string) ([]GroupResponse, error) {
	query := `SELECT g.id, g.name, g.description, g.created_at, g.updated_at
		FROM groups g
		JOIN user_groups ug ON g.id = ug.group_id
		WHERE ug.user_id = ?
		ORDER BY g.name`
	rows, err := db.GetDB().Query(query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get groups for user: %w", err)
	}
	defer rows.Close()

	var groups []GroupResponse
	for rows.Next() {
		var g GroupResponse
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.CreatedAt, &g.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan group: %w", err)
		}
		groups = append(groups, g)
	}
	if groups == nil {
		groups = []GroupResponse{}
	}
	return groups, nil
}

func MembersByGroupID(groupID string) ([]GroupMemberResponse, error) {
	query := `SELECT u.id, u.username, u.email, ug.created_at
		FROM users u
		JOIN user_groups ug ON u.id = ug.user_id
		WHERE ug.group_id = ?
		ORDER BY u.username`
	rows, err := db.GetDB().Query(query, groupID)
	if err != nil {
		return nil, fmt.Errorf("failed to get members: %w", err)
	}
	defer rows.Close()

	var members []GroupMemberResponse
	for rows.Next() {
		var m GroupMemberResponse
		var email *string
		if err := rows.Scan(&m.UserID, &m.Username, &email, &m.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan member: %w", err)
		}
		if email != nil {
			m.Email = *email
		}
		members = append(members, m)
	}
	if members == nil {
		members = []GroupMemberResponse{}
	}
	return members, nil
}

// GroupNamesByUserID returns just the group name strings for a user.
// Used for embedding in token claims and userinfo responses.
func GroupNamesByUserID(userID string) ([]string, error) {
	query := `SELECT g.name FROM groups g
		JOIN user_groups ug ON g.id = ug.group_id
		WHERE ug.user_id = ?
		ORDER BY g.name`
	rows, err := db.GetDB().Query(query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get group names: %w", err)
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("failed to scan group name: %w", err)
		}
		names = append(names, name)
	}
	return names, nil
}
