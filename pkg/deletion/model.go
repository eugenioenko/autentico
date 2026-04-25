package deletion

import (
	"database/sql"
	"time"
)

type DeletionRequest struct {
	ID          string
	UserID      string
	Username    string
	Email       string
	Reason      sql.NullString
	RequestedAt time.Time
}

type DeletionRequestResponse struct {
	ID          string    `json:"id"`
	UserID      string    `json:"user_id"`
	Username    string    `json:"username"`
	Email       string    `json:"email"`
	Reason      *string   `json:"reason,omitempty"`
	RequestedAt time.Time `json:"requested_at"`
}

func (d *DeletionRequest) ToResponse() DeletionRequestResponse {
	var reason *string
	if d.Reason.Valid {
		reason = &d.Reason.String
	}
	return DeletionRequestResponse{
		ID:          d.ID,
		UserID:      d.UserID,
		Username:    d.Username,
		Email:       d.Email,
		Reason:      reason,
		RequestedAt: d.RequestedAt,
	}
}

type CreateDeletionRequestInput struct {
	Reason string `json:"reason,omitempty"`
}
