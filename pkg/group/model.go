package group

import (
	"fmt"
	"regexp"
	"time"

	validation "github.com/go-ozzo/ozzo-validation"
)

var groupNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

type Group struct {
	ID          string
	Name        string
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type GroupResponse struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	MemberCount int       `json:"member_count"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (g *Group) ToResponse() GroupResponse {
	return GroupResponse{
		ID:          g.ID,
		Name:        g.Name,
		Description: g.Description,
		CreatedAt:   g.CreatedAt,
		UpdatedAt:   g.UpdatedAt,
	}
}

type GroupCreateRequest struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type GroupUpdateRequest struct {
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

type GroupMemberRequest struct {
	UserID string `json:"user_id"`
}

type GroupMemberResponse struct {
	UserID    string    `json:"user_id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

func ValidateGroupCreateRequest(input GroupCreateRequest) error {
	if err := validation.Validate(input.Name,
		validation.Required,
		validation.Length(1, 100),
		validation.Match(groupNameRegex),
	); err != nil {
		return fmt.Errorf("name is invalid: %w", err)
	}
	if len(input.Description) > 500 {
		return fmt.Errorf("description is invalid: must be at most 500 characters")
	}
	return nil
}

func ValidateGroupUpdateRequest(input GroupUpdateRequest) error {
	if input.Name != "" {
		if err := validation.Validate(input.Name,
			validation.Length(1, 100),
			validation.Match(groupNameRegex),
		); err != nil {
			return fmt.Errorf("name is invalid: %w", err)
		}
	}
	if len(input.Description) > 500 {
		return fmt.Errorf("description is invalid: must be at most 500 characters")
	}
	return nil
}
