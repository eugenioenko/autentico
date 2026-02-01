package client

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/eugenioenko/autentico/pkg/db"
)

// ClientByID retrieves a client by its internal ID
func ClientByID(id string) (*Client, error) {
	query := `
		SELECT id, client_id, client_secret, client_name, client_type,
			redirect_uris, grant_types, response_types, scopes,
			token_endpoint_auth_method, is_active, created_at, updated_at
		FROM clients
		WHERE id = ?
	`

	var client Client
	var clientSecret sql.NullString
	err := db.GetDB().QueryRow(query, id).Scan(
		&client.ID,
		&client.ClientID,
		&clientSecret,
		&client.ClientName,
		&client.ClientType,
		&client.RedirectURIs,
		&client.GrantTypes,
		&client.ResponseTypes,
		&client.Scopes,
		&client.TokenEndpointAuthMethod,
		&client.IsActive,
		&client.CreatedAt,
		&client.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("client not found")
		}
		return nil, err
	}

	if clientSecret.Valid {
		client.ClientSecret = clientSecret.String
	}

	return &client, nil
}

// ClientByClientID retrieves a client by its public client_id
func ClientByClientID(clientID string) (*Client, error) {
	query := `
		SELECT id, client_id, client_secret, client_name, client_type,
			redirect_uris, grant_types, response_types, scopes,
			token_endpoint_auth_method, is_active, created_at, updated_at
		FROM clients
		WHERE client_id = ?
	`

	var client Client
	var clientSecret sql.NullString
	err := db.GetDB().QueryRow(query, clientID).Scan(
		&client.ID,
		&client.ClientID,
		&clientSecret,
		&client.ClientName,
		&client.ClientType,
		&client.RedirectURIs,
		&client.GrantTypes,
		&client.ResponseTypes,
		&client.Scopes,
		&client.TokenEndpointAuthMethod,
		&client.IsActive,
		&client.CreatedAt,
		&client.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("client not found")
		}
		return nil, err
	}

	if clientSecret.Valid {
		client.ClientSecret = clientSecret.String
	}

	return &client, nil
}

// ListClients retrieves all active clients
func ListClients() ([]*Client, error) {
	query := `
		SELECT id, client_id, client_secret, client_name, client_type,
			redirect_uris, grant_types, response_types, scopes,
			token_endpoint_auth_method, is_active, created_at, updated_at
		FROM clients
		WHERE is_active = TRUE
		ORDER BY created_at DESC
	`

	rows, err := db.GetDB().Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var clients []*Client
	for rows.Next() {
		var client Client
		var clientSecret sql.NullString
		err := rows.Scan(
			&client.ID,
			&client.ClientID,
			&clientSecret,
			&client.ClientName,
			&client.ClientType,
			&client.RedirectURIs,
			&client.GrantTypes,
			&client.ResponseTypes,
			&client.Scopes,
			&client.TokenEndpointAuthMethod,
			&client.IsActive,
			&client.CreatedAt,
			&client.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		if clientSecret.Valid {
			client.ClientSecret = clientSecret.String
		}

		clients = append(clients, &client)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return clients, nil
}
