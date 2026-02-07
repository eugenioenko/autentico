package client

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/rs/xid"
	"golang.org/x/crypto/bcrypt"
)

// CreateClient creates a new OAuth2 client in the database
// Returns the client response with the plain text secret (shown only once)
func CreateClient(request ClientCreateRequest) (*ClientResponse, error) {
	id := xid.New().String()

	clientID, err := GenerateClientID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate client ID: %w", err)
	}

	// Set defaults
	clientType := request.ClientType
	if clientType == "" {
		clientType = "confidential"
	}

	grantTypes := request.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code"}
	}

	responseTypes := request.ResponseTypes
	if len(responseTypes) == 0 {
		responseTypes = []string{"code"}
	}

	scopes := request.Scopes
	if scopes == "" {
		scopes = "openid profile email"
	}

	tokenEndpointAuthMethod := request.TokenEndpointAuthMethod
	if tokenEndpointAuthMethod == "" {
		if clientType == "public" {
			tokenEndpointAuthMethod = "none"
		} else {
			tokenEndpointAuthMethod = "client_secret_basic"
		}
	}

	// Generate and hash client secret for confidential clients
	var plainSecret string
	var hashedSecret *string
	if clientType == "confidential" {
		plainSecret, err = GenerateClientSecret()
		if err != nil {
			return nil, fmt.Errorf("failed to generate client secret: %w", err)
		}
		hashedSecretBytes, err := bcrypt.GenerateFromPassword([]byte(plainSecret), bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("failed to hash client secret: %w", err)
		}
		hashedSecretStr := string(hashedSecretBytes)
		hashedSecret = &hashedSecretStr
	}

	// Serialize arrays to JSON
	redirectURIsJSON, err := json.Marshal(request.RedirectURIs)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize redirect URIs: %w", err)
	}

	grantTypesJSON, err := json.Marshal(grantTypes)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize grant types: %w", err)
	}

	responseTypesJSON, err := json.Marshal(responseTypes)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize response types: %w", err)
	}

	query := `
		INSERT INTO clients (
			id, client_id, client_secret, client_name, client_type,
			redirect_uris, grant_types, response_types, scopes,
			token_endpoint_auth_method, is_active, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	now := time.Now().UTC()
	_, err = db.GetDB().Exec(query,
		id,
		clientID,
		hashedSecret,
		request.ClientName,
		clientType,
		string(redirectURIsJSON),
		string(grantTypesJSON),
		string(responseTypesJSON),
		scopes,
		tokenEndpointAuthMethod,
		true,
		now,
		now,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	return &ClientResponse{
		ClientID:                clientID,
		ClientSecret:            plainSecret,
		ClientSecretExpiresAt:   0,
		ClientName:              request.ClientName,
		ClientType:              clientType,
		RedirectURIs:            request.RedirectURIs,
		GrantTypes:              grantTypes,
		ResponseTypes:           responseTypes,
		Scopes:                  scopes,
		TokenEndpointAuthMethod: tokenEndpointAuthMethod,
	}, nil
}
