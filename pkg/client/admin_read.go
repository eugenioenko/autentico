package client

import (
	"database/sql"
	"fmt"

	"github.com/eugenioenko/autentico/pkg/db"
)

// ClientByClientIDIncludingDisabled returns the client regardless of is_active status.
// Used by admin endpoints that need to view or modify deactivated clients.
func ClientByClientIDIncludingDisabled(clientID string) (*Client, error) {
	query := `
		SELECT
			id, client_id, client_secret, client_name, client_type, redirect_uris,
			post_logout_redirect_uris, grant_types, response_types, scopes,
			token_endpoint_auth_method, is_active, created_at, updated_at,
			access_token_expiration, refresh_token_expiration, authorization_code_expiration,
			allowed_audiences, allow_self_signup, sso_session_idle_timeout,
			trust_device_enabled, trust_device_expiration
		FROM clients WHERE client_id = ?
	`
	var c Client
	var secret sql.NullString
	var audiences sql.NullString
	err := db.GetReadDB().QueryRow(query, clientID).Scan(
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

// ClientByIDIncludingDisabled returns the client regardless of is_active status.
// Used by admin endpoints that need to view or modify deactivated clients.
func ClientByIDIncludingDisabled(id string) (*Client, error) {
	query := `
		SELECT
			id, client_id, client_secret, client_name, client_type, redirect_uris,
			post_logout_redirect_uris, grant_types, response_types, scopes,
			token_endpoint_auth_method, is_active, created_at, updated_at,
			access_token_expiration, refresh_token_expiration, authorization_code_expiration,
			allowed_audiences, allow_self_signup, sso_session_idle_timeout,
			trust_device_enabled, trust_device_expiration
		FROM clients WHERE id = ?
	`
	var c Client
	var secret sql.NullString
	var audiences sql.NullString
	err := db.GetReadDB().QueryRow(query, id).Scan(
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
