package client

import (
	"database/sql"
	"fmt"

	"github.com/eugenioenko/autentico/pkg/db"
)

func ListClients() ([]*Client, error) {
	query := `
		SELECT 
			id, client_id, client_secret, client_name, client_type, redirect_uris, 
			post_logout_redirect_uris, grant_types, response_types, scopes, 
			token_endpoint_auth_method, is_active, created_at, updated_at,
			access_token_expiration, refresh_token_expiration, authorization_code_expiration,
			allowed_audiences, allow_self_signup, sso_session_idle_timeout,
			trust_device_enabled, trust_device_expiration, is_admin_service_account
		FROM clients WHERE is_active = 1 ORDER BY created_at DESC
	`
	rows, err := db.GetDB().Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to list clients: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var clients []*Client
	for rows.Next() {
		var c Client
		var secret sql.NullString
		var audiences sql.NullString
		if err := rows.Scan(
			&c.ID, &c.ClientID, &secret, &c.ClientName, &c.ClientType, &c.RedirectURIs,
			&c.PostLogoutRedirectURIs, &c.GrantTypes, &c.ResponseTypes, &c.Scopes,
			&c.TokenEndpointAuthMethod, &c.IsActive, &c.CreatedAt, &c.UpdatedAt,
			&c.AccessTokenExpiration, &c.RefreshTokenExpiration, &c.AuthorizationCodeExpiration,
			&audiences, &c.AllowSelfSignup, &c.SsoSessionIdleTimeout,
			&c.TrustDeviceEnabled, &c.TrustDeviceExpiration, &c.IsAdminServiceAccount,
		); err != nil {
			return nil, fmt.Errorf("failed to scan client: %w", err)
		}
		if secret.Valid {
			c.ClientSecret = secret.String
		}
		if audiences.Valid {
			c.AllowedAudiences = &audiences.String
		}
		clients = append(clients, &c)
	}
	return clients, rows.Err()
}

func ClientByClientID(clientID string) (*Client, error) {
	query := `
		SELECT 
			id, client_id, client_secret, client_name, client_type, redirect_uris, 
			post_logout_redirect_uris, grant_types, response_types, scopes, 
			token_endpoint_auth_method, is_active, created_at, updated_at,
			access_token_expiration, refresh_token_expiration, authorization_code_expiration,
			allowed_audiences, allow_self_signup, sso_session_idle_timeout,
			trust_device_enabled, trust_device_expiration, is_admin_service_account
		FROM clients WHERE client_id = ?
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
		&c.TrustDeviceEnabled, &c.TrustDeviceExpiration, &c.IsAdminServiceAccount,
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
			trust_device_enabled, trust_device_expiration, is_admin_service_account
		FROM clients WHERE id = ?
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
		&c.TrustDeviceEnabled, &c.TrustDeviceExpiration, &c.IsAdminServiceAccount,
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
