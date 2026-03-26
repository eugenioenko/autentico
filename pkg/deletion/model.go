package deletion

import (
	"database/sql"
	"time"
)

type DeletionRequest struct {
	ID          string
	UserID      string
	Reason      sql.NullString
	RequestedAt time.Time
}

type DeletionRequestResponse struct {
	ID          string    `json:"id"`
	UserID      string    `json:"user_id"`
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
		Reason:      reason,
		RequestedAt: d.RequestedAt,
	}
}

type CreateDeletionRequestInput struct {
	Reason string `json:"reason,omitempty"`
}
