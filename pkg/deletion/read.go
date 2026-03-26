package deletion

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
)

func scanDeletionRequest(row interface{ Scan(dest ...any) error }) (*DeletionRequest, error) {
	var req DeletionRequest
	var requestedAt string
	if err := row.Scan(&req.ID, &req.UserID, &req.Reason, &requestedAt); err != nil {
		return nil, err
	}
	for _, layout := range []string{"2006-01-02 15:04:05", time.RFC3339, time.RFC3339Nano} {
		if t, err := time.Parse(layout, requestedAt); err == nil {
			req.RequestedAt = t
			break
		}
	}
	return &req, nil
}

func DeletionRequestByUserID(userID string) (*DeletionRequest, error) {
	row := db.GetDB().QueryRow(
		`SELECT id, user_id, reason, requested_at FROM deletion_requests WHERE user_id = ? LIMIT 1`,
		userID,
	)
	req, err := scanDeletionRequest(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get deletion request: %w", err)
	}
	return req, nil
}

func DeletionRequestByID(id string) (*DeletionRequest, error) {
	row := db.GetDB().QueryRow(
		`SELECT id, user_id, reason, requested_at FROM deletion_requests WHERE id = ? LIMIT 1`,
		id,
	)
	req, err := scanDeletionRequest(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get deletion request: %w", err)
	}
	return req, nil
}

func ListDeletionRequests() ([]DeletionRequest, error) {
	rows, err := db.GetDB().Query(
		`SELECT id, user_id, reason, requested_at FROM deletion_requests ORDER BY requested_at ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list deletion requests: %w", err)
	}
	defer rows.Close()

	var result []DeletionRequest
	for rows.Next() {
		req, err := scanDeletionRequest(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan deletion request: %w", err)
		}
		result = append(result, *req)
	}
	if result == nil {
		result = []DeletionRequest{}
	}
	return result, nil
}
