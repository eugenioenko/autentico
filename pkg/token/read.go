package token

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/eugenioenko/autentico/pkg/api"
	"github.com/eugenioenko/autentico/pkg/db"
)

// TokenByAccessToken returns the active token row matching the access token.
// Revoked tokens are filtered at the read layer so callers can't accidentally
// honor a revoked token.
//
// Returns sql.ErrNoRows when no active row exists. A JWT that validated
// cryptographically but has no matching active row means either (a) the
// token was revoked via /oauth2/revoke, (b) its tokens row was cleaned up
// because the refresh token expired (only possible if refresh_token_expiration
// is misconfigured shorter than access_token_expiration), or (c) the JWT was
// forged (impossible with an uncompromised signing key). Callers should
// treat this as a rejection, not a pass.
func TokenByAccessToken(accessToken string) (*Token, error) {
	var t Token
	err := db.GetReadDB().QueryRow(`
		SELECT id, user_id, access_token, refresh_token, access_token_type,
			refresh_token_expires_at, refresh_token_last_used_at,
			access_token_expires_at, issued_at, scope, grant_type, revoked_at
		FROM tokens WHERE access_token = ? AND revoked_at IS NULL
	`, accessToken).Scan(
		&t.ID, &t.UserID, &t.AccessToken, &t.RefreshToken, &t.AccessTokenType,
		&t.RefreshTokenExpiresAt, &t.RefreshTokenLastUsedAt,
		&t.AccessTokenExpiresAt, &t.IssuedAt, &t.Scope, &t.GrantType, &t.RevokedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, err
		}
		return nil, fmt.Errorf("failed to get token: %w", err)
	}
	return &t, nil
}

var tokenListConfig = api.ListConfig{
	AllowedSort: map[string]bool{
		"issued_at":               true,
		"access_token_expires_at": true,
	},
	SearchColumns:  []string{},
	AllowedFilters: map[string]bool{},
	DefaultSort:    "issued_at",
	MaxLimit:       api.DefaultMaxLimit,
	TableAlias:     "t",
}

type TokenRow struct {
	ID                    string
	UserID                *string
	Username              string
	Email                 string
	Scope                 string
	GrantType             string
	AccessTokenExpiresAt  time.Time
	IssuedAt              time.Time
	RevokedAt             *time.Time
}

func ListTokensWithParams(params api.ListParams, dateWhere string, dateArgs []any) ([]TokenRow, int, error) {
	var searchWhere string
	var searchArgs []any
	if params.Search != "" {
		pattern := "%" + params.Search + "%"
		searchWhere = " AND (u.username LIKE ? OR u.email LIKE ?)"
		searchArgs = []any{pattern, pattern}
	}
	params.Search = ""

	lq := api.BuildListQuery(params, tokenListConfig)

	baseFrom := "FROM tokens t LEFT JOIN users u ON t.user_id = u.id"
	baseWhere := "WHERE 1=1"
	allArgs := append(dateArgs, searchArgs...)
	allArgs = append(allArgs, lq.Args...)

	var total int
	countQuery := "SELECT COUNT(*) " + baseFrom + " " + baseWhere + dateWhere + searchWhere + lq.Where
	if err := db.GetReadDB().QueryRow(countQuery, allArgs...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count tokens: %w", err)
	}

	query := `SELECT t.id, t.user_id, COALESCE(u.username, ''), COALESCE(u.email, ''),
		t.scope, t.grant_type, t.access_token_expires_at, t.issued_at, t.revoked_at
		` + baseFrom + ` ` + baseWhere + dateWhere + searchWhere + lq.Where + lq.Order
	rows, err := db.GetReadDB().Query(query, allArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list tokens: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []TokenRow
	for rows.Next() {
		var r TokenRow
		if err := rows.Scan(&r.ID, &r.UserID, &r.Username, &r.Email,
			&r.Scope, &r.GrantType, &r.AccessTokenExpiresAt, &r.IssuedAt, &r.RevokedAt); err != nil {
			return nil, 0, fmt.Errorf("failed to scan token row: %w", err)
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}
