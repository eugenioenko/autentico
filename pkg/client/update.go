package client

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
)

// UpdateClient updates an existing OAuth2 client
func UpdateClient(clientID string, request ClientUpdateRequest) (*ClientInfoResponse, error) {
	// First, get the existing client
	existingClient, err := ClientByClientID(clientID)
	if err != nil {
		return nil, err
	}

	// Build the update query dynamically based on provided fields
	clientName := existingClient.ClientName
	if request.ClientName != "" {
		clientName = request.ClientName
	}

	redirectURIs := existingClient.RedirectURIs
	if len(request.RedirectURIs) > 0 {
		redirectURIsJSON, err := json.Marshal(request.RedirectURIs)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize redirect URIs: %w", err)
		}
		redirectURIs = string(redirectURIsJSON)
	}

	grantTypes := existingClient.GrantTypes
	if len(request.GrantTypes) > 0 {
		grantTypesJSON, err := json.Marshal(request.GrantTypes)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize grant types: %w", err)
		}
		grantTypes = string(grantTypesJSON)
	}

	responseTypes := existingClient.ResponseTypes
	if len(request.ResponseTypes) > 0 {
		responseTypesJSON, err := json.Marshal(request.ResponseTypes)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize response types: %w", err)
		}
		responseTypes = string(responseTypesJSON)
	}

	scopes := existingClient.Scopes
	if request.Scopes != "" {
		scopes = request.Scopes
	}

	tokenEndpointAuthMethod := existingClient.TokenEndpointAuthMethod
	if request.TokenEndpointAuthMethod != "" {
		tokenEndpointAuthMethod = request.TokenEndpointAuthMethod
	}

	isActive := existingClient.IsActive
	if request.IsActive != nil {
		isActive = *request.IsActive
	}

	accessTokenExpiration := existingClient.AccessTokenExpiration
	if request.AccessTokenExpiration != nil {
		accessTokenExpiration = request.AccessTokenExpiration
	}

	refreshTokenExpiration := existingClient.RefreshTokenExpiration
	if request.RefreshTokenExpiration != nil {
		refreshTokenExpiration = request.RefreshTokenExpiration
	}

	authorizationCodeExpiration := existingClient.AuthorizationCodeExpiration
	if request.AuthorizationCodeExpiration != nil {
		authorizationCodeExpiration = request.AuthorizationCodeExpiration
	}

	allowedAudiences := existingClient.AllowedAudiences
	if request.AllowedAudiences != nil {
		aud, _ := json.Marshal(request.AllowedAudiences)
		audStr := string(aud)
		allowedAudiences = &audStr
	}

	allowSelfSignup := existingClient.AllowSelfSignup
	if request.AllowSelfSignup != nil {
		allowSelfSignup = request.AllowSelfSignup
	}

	ssoSessionIdleTimeout := existingClient.SsoSessionIdleTimeout
	if request.SsoSessionIdleTimeout != nil {
		ssoSessionIdleTimeout = request.SsoSessionIdleTimeout
	}

	trustDeviceEnabled := existingClient.TrustDeviceEnabled
	if request.TrustDeviceEnabled != nil {
		trustDeviceEnabled = request.TrustDeviceEnabled
	}

	trustDeviceExpiration := existingClient.TrustDeviceExpiration
	if request.TrustDeviceExpiration != nil {
		trustDeviceExpiration = request.TrustDeviceExpiration
	}

	query := `
		UPDATE clients SET
			client_name = ?,
			redirect_uris = ?,
			grant_types = ?,
			response_types = ?,
			scopes = ?,
			token_endpoint_auth_method = ?,
			is_active = ?,
			updated_at = ?,
			access_token_expiration = ?,
			refresh_token_expiration = ?,
			authorization_code_expiration = ?,
			allowed_audiences = ?,
			allow_self_signup = ?,
			sso_session_idle_timeout = ?,
			trust_device_enabled = ?,
			trust_device_expiration = ?
		WHERE client_id = ?
	`

	now := time.Now().UTC()
	_, err = db.GetDB().Exec(query,
		clientName,
		redirectURIs,
		grantTypes,
		responseTypes,
		scopes,
		tokenEndpointAuthMethod,
		isActive,
		now,
		accessTokenExpiration,
		refreshTokenExpiration,
		authorizationCodeExpiration,
		allowedAudiences,
		allowSelfSignup,
		ssoSessionIdleTimeout,
		trustDeviceEnabled,
		trustDeviceExpiration,
		clientID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to update client: %w", err)
	}

	// Return the updated client info
	updatedClient, err := ClientByClientID(clientID)
	if err != nil {
		return nil, err
	}

	return updatedClient.ToInfoResponse(), nil
}
