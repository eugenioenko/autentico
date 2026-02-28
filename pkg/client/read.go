package client

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/eugenioenko/autentico/pkg/db"
)

const selectColumns = `
	id, client_id, client_secret, client_name, client_type,
	redirect_uris, grant_types, response_types, scopes,
	token_endpoint_auth_method, is_active, created_at, updated_at,
	access_token_expiration, refresh_token_expiration, authorization_code_expiration,
	allowed_audiences, allow_self_signup, sso_session_idle_timeout,
	trust_device_enabled, trust_device_expiration
`

// scanClient scans a row into a Client struct, handling nullable columns.
func scanClient(scanner interface {
	Scan(dest ...any) error
}) (*Client, error) {
	var c Client
	var clientSecret sql.NullString
	var accessTokenExp, refreshTokenExp, authCodeExp, allowedAud, ssoTimeout, trustDevExp sql.NullString
	var allowSelfSignup, trustDevEnabled sql.NullInt64

	err := scanner.Scan(
		&c.ID, &c.ClientID, &clientSecret, &c.ClientName, &c.ClientType,
		&c.RedirectURIs, &c.GrantTypes, &c.ResponseTypes, &c.Scopes,
		&c.TokenEndpointAuthMethod, &c.IsActive, &c.CreatedAt, &c.UpdatedAt,
		&accessTokenExp, &refreshTokenExp, &authCodeExp,
		&allowedAud, &allowSelfSignup, &ssoTimeout,
		&trustDevEnabled, &trustDevExp,
	)
	if err != nil {
		return nil, err
	}

	if clientSecret.Valid {
		c.ClientSecret = clientSecret.String
	}
	if accessTokenExp.Valid {
		c.AccessTokenExpiration = &accessTokenExp.String
	}
	if refreshTokenExp.Valid {
		c.RefreshTokenExpiration = &refreshTokenExp.String
	}
	if authCodeExp.Valid {
		c.AuthorizationCodeExpiration = &authCodeExp.String
	}
	if allowedAud.Valid {
		c.AllowedAudiences = &allowedAud.String
	}
	if allowSelfSignup.Valid {
		b := allowSelfSignup.Int64 != 0
		c.AllowSelfSignup = &b
	}
	if ssoTimeout.Valid {
		c.SsoSessionIdleTimeout = &ssoTimeout.String
	}
	if trustDevEnabled.Valid {
		b := trustDevEnabled.Int64 != 0
		c.TrustDeviceEnabled = &b
	}
	if trustDevExp.Valid {
		c.TrustDeviceExpiration = &trustDevExp.String
	}

	return &c, nil
}

// ClientByID retrieves a client by its internal ID
func ClientByID(id string) (*Client, error) {
	query := `SELECT ` + selectColumns + ` FROM clients WHERE id = ?`
	row := db.GetDB().QueryRow(query, id)
	c, err := scanClient(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("client not found")
		}
		return nil, err
	}
	return c, nil
}

// ClientByClientID retrieves a client by its public client_id
func ClientByClientID(clientID string) (*Client, error) {
	query := `SELECT ` + selectColumns + ` FROM clients WHERE client_id = ?`
	row := db.GetDB().QueryRow(query, clientID)
	c, err := scanClient(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("client not found")
		}
		return nil, err
	}
	return c, nil
}

// ClientByName retrieves an active client by its client_name
func ClientByName(name string) (*Client, error) {
	query := `SELECT ` + selectColumns + ` FROM clients WHERE client_name = ? AND is_active = TRUE`
	row := db.GetDB().QueryRow(query, name)
	c, err := scanClient(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("client not found")
		}
		return nil, err
	}
	return c, nil
}

// ListClients retrieves all active clients
func ListClients() ([]*Client, error) {
	query := `SELECT ` + selectColumns + ` FROM clients WHERE is_active = TRUE ORDER BY created_at DESC`

	rows, err := db.GetDB().Query(query)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var clients []*Client
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		clients = append(clients, c)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return clients, nil
}
