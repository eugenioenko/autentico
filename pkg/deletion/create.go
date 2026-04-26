package deletion

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/rs/xid"
)

func CreateDeletionRequest(userID string, reason *string) (*DeletionRequest, error) {
	id := xid.New().String()
	now := time.Now()

	var ns sql.NullString
	if reason != nil {
		ns = sql.NullString{String: *reason, Valid: true}
	}

	_, err := db.GetWriteDB().Exec(
		`INSERT INTO deletion_requests (id, user_id, reason, requested_at) VALUES (?, ?, ?, datetime('now'))`,
		id, userID, ns,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create deletion request: %w", err)
	}
	return &DeletionRequest{
		ID:          id,
		UserID:      userID,
		Reason:      ns,
		RequestedAt: now,
	}, nil
}
