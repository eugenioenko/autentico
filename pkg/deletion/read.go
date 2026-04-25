package deletion

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/eugenioenko/autentico/pkg/api"
	"github.com/eugenioenko/autentico/pkg/db"
)

var deletionListConfig = api.ListConfig{
	AllowedSort: map[string]bool{
		"d.requested_at": true,
		"u.username":     true,
		"u.email":        true,
	},
	SearchColumns:  []string{},
	AllowedFilters: map[string]bool{},
	DefaultSort:    "d.requested_at",
	MaxLimit:       api.DefaultMaxLimit,
}

var deletionSortMap = map[string]string{
	"requested_at": "d.requested_at",
	"username":     "u.username",
	"email":        "u.email",
}

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

func scanDeletionRequestWithUser(row interface{ Scan(dest ...any) error }) (*DeletionRequest, error) {
	var req DeletionRequest
	var requestedAt string
	var username, email sql.NullString
	if err := row.Scan(&req.ID, &req.UserID, &req.Reason, &requestedAt, &username, &email); err != nil {
		return nil, err
	}
	req.Username = username.String
	req.Email = email.String
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

func ListDeletionRequestsWithParams(params api.ListParams, dateWhere string, dateArgs []any) ([]DeletionRequest, int, error) {
	if mapped, ok := deletionSortMap[params.Sort]; ok {
		params.Sort = mapped
	}

	var searchWhere string
	var searchArgs []any
	if params.Search != "" {
		pattern := "%" + params.Search + "%"
		searchWhere = " AND (u.username LIKE ? OR u.email LIKE ? OR d.reason LIKE ?)"
		searchArgs = []any{pattern, pattern, pattern}
	}
	params.Search = ""

	lq := api.BuildListQuery(params, deletionListConfig)

	baseFrom := "FROM deletion_requests d LEFT JOIN users u ON d.user_id = u.id WHERE 1=1"
	allArgs := append(dateArgs, searchArgs...)
	allArgs = append(allArgs, lq.Args...)

	var total int
	countQuery := "SELECT COUNT(*) " + baseFrom + dateWhere + searchWhere + lq.Where
	if err := db.GetDB().QueryRow(countQuery, allArgs...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count deletion requests: %w", err)
	}

	query := "SELECT d.id, d.user_id, d.reason, d.requested_at, u.username, u.email " + baseFrom + dateWhere + searchWhere + lq.Where + lq.Order
	rows, err := db.GetDB().Query(query, allArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list deletion requests: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var result []DeletionRequest
	for rows.Next() {
		req, err := scanDeletionRequestWithUser(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan deletion request: %w", err)
		}
		result = append(result, *req)
	}
	if result == nil {
		result = []DeletionRequest{}
	}
	return result, total, nil
}
