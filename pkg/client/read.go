package client

import (
	"database/sql"
	"fmt"

	"github.com/eugenioenko/autentico/pkg/api"
	"github.com/eugenioenko/autentico/pkg/db"
)

var clientListConfig = api.ListConfig{
	AllowedSort: map[string]bool{
		"created_at":  true,
		"client_name": true,
		"client_id":   true,
		"client_type": true,
	},
	SearchColumns: []string{
		"client_name", "client_id",
	},
	AllowedFilters: map[string]bool{
		"client_type": true,
		"is_active":   true,
	},
	DefaultSort: "created_at",
	MaxLimit:    200,
}

var clientColumns = `id, client_id, client_secret, client_name, client_type, redirect_uris,
	post_logout_redirect_uris, grant_types, response_types, scopes,
	token_endpoint_auth_method, is_active, created_at, updated_at,
	access_token_expiration, refresh_token_expiration, authorization_code_expiration,
	allowed_audiences, allow_self_signup, sso_session_idle_timeout,
	trust_device_enabled, trust_device_expiration`

func scanClient(rows *sql.Rows) (*Client, error) {
	var c Client
	var secret sql.NullString
	var audiences sql.NullString
	if err := rows.Scan(
		&c.ID, &c.ClientID, &secret, &c.ClientName, &c.ClientType, &c.RedirectURIs,
		&c.PostLogoutRedirectURIs, &c.GrantTypes, &c.ResponseTypes, &c.Scopes,
		&c.TokenEndpointAuthMethod, &c.IsActive, &c.CreatedAt, &c.UpdatedAt,
		&c.AccessTokenExpiration, &c.RefreshTokenExpiration, &c.AuthorizationCodeExpiration,
		&audiences, &c.AllowSelfSignup, &c.SsoSessionIdleTimeout,
		&c.TrustDeviceEnabled, &c.TrustDeviceExpiration,
	); err != nil {
		return nil, err
	}
	if secret.Valid {
		c.ClientSecret = secret.String
	}
	if audiences.Valid {
		c.AllowedAudiences = &audiences.String
	}
	return &c, nil
}

func ListClientsWithParams(params api.ListParams) ([]*Client, int, error) {
	lq := api.BuildListQuery(params, clientListConfig)

	baseWhere := "WHERE 1=1"

	var total int
	countQuery := "SELECT COUNT(*) FROM clients " + baseWhere + lq.Where
	if err := db.GetDB().QueryRow(countQuery, lq.Args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count clients: %w", err)
	}

	query := `SELECT ` + clientColumns + ` FROM clients ` + baseWhere + lq.Where + lq.Order
	rows, err := db.GetDB().Query(query, lq.Args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list clients: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var clients []*Client
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan client: %w", err)
		}
		clients = append(clients, c)
	}
	if clients == nil {
		clients = []*Client{}
	}
	return clients, total, rows.Err()
}

func ClientByClientID(clientID string) (*Client, error) {
	query := `
		SELECT 
			id, client_id, client_secret, client_name, client_type, redirect_uris, 
			post_logout_redirect_uris, grant_types, response_types, scopes, 
			token_endpoint_auth_method, is_active, created_at, updated_at,
			access_token_expiration, refresh_token_expiration, authorization_code_expiration,
			allowed_audiences, allow_self_signup, sso_session_idle_timeout,
			trust_device_enabled, trust_device_expiration
		FROM clients WHERE client_id = ? AND is_active = 1
	`
	var c Client
	var secret sql.NullString
	var audiences sql.NullString
	err := db.GetDB().QueryRow(query, clientID).Scan(
		&c.ID, &c.ClientID, &secret, &c.ClientName, &c.ClientType, &c.RedirectURIs,
		&c.PostLogoutRedirectURIs, &c.GrantTypes, &c.ResponseTypes, &c.Scopes,
		&c.TokenEndpointAuthMethod, &c.IsActive, &c.CreatedAt, &c.UpdatedAt,
		&c.AccessTokenExpiration, &c.RefreshTokenExpiration, &c.AuthorizationCodeExpiration,
		&audiences, &c.AllowSelfSignup, &c.SsoSessionIdleTimeout,
		&c.TrustDeviceEnabled, &c.TrustDeviceExpiration,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("client not found")
		}
		return nil, fmt.Errorf("failed to get client: %w", err)
	}
	if secret.Valid {
		c.ClientSecret = secret.String
	}
	if audiences.Valid {
		c.AllowedAudiences = &audiences.String
	}
	return &c, nil
}

func ClientByID(id string) (*Client, error) {
	query := `
		SELECT 
			id, client_id, client_secret, client_name, client_type, redirect_uris, 
			post_logout_redirect_uris, grant_types, response_types, scopes, 
			token_endpoint_auth_method, is_active, created_at, updated_at,
			access_token_expiration, refresh_token_expiration, authorization_code_expiration,
			allowed_audiences, allow_self_signup, sso_session_idle_timeout,
			trust_device_enabled, trust_device_expiration
		FROM clients WHERE id = ? AND is_active = 1
	`
	var c Client
	var secret sql.NullString
	var audiences sql.NullString
	err := db.GetDB().QueryRow(query, id).Scan(
		&c.ID, &c.ClientID, &secret, &c.ClientName, &c.ClientType, &c.RedirectURIs,
		&c.PostLogoutRedirectURIs, &c.GrantTypes, &c.ResponseTypes, &c.Scopes,
		&c.TokenEndpointAuthMethod, &c.IsActive, &c.CreatedAt, &c.UpdatedAt,
		&c.AccessTokenExpiration, &c.RefreshTokenExpiration, &c.AuthorizationCodeExpiration,
		&audiences, &c.AllowSelfSignup, &c.SsoSessionIdleTimeout,
		&c.TrustDeviceEnabled, &c.TrustDeviceExpiration,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("client not found")
		}
		return nil, fmt.Errorf("failed to get client: %w", err)
	}
	if secret.Valid {
		c.ClientSecret = secret.String
	}
	if audiences.Valid {
		c.AllowedAudiences = &audiences.String
	}
	return &c, nil
}
