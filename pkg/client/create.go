package client

import (
	"encoding/json"
	"fmt"

	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/db"
	"golang.org/x/crypto/bcrypt"
)

func CreateClient(req ClientCreateRequest) (*ClientResponse, error) {
	clientID, err := authcode.GenerateSecureCode()
	if err != nil {
		return nil, fmt.Errorf("failed to generate client id: %w", err)
	}
	return createClientInternal(clientID, req)
}

func CreateClientWithID(clientID string, req ClientCreateRequest) error {
	_, err := createClientInternal(clientID, req)
	return err
}

func createClientInternal(clientID string, req ClientCreateRequest) (*ClientResponse, error) {
	clientSecret := ""
	hashedSecret := ""
	if req.ClientType != "public" {
		var err error
		clientSecret, err = authcode.GenerateSecureCode()
		if err != nil {
			return nil, fmt.Errorf("failed to generate client secret: %w", err)
		}
		hashed, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("failed to hash client secret: %w", err)
		}
		hashedSecret = string(hashed)
	}

	redirectURIs, _ := json.Marshal(req.RedirectURIs)
	
	postLogoutURIsSlice := req.PostLogoutRedirectURIs
	if postLogoutURIsSlice == nil {
		postLogoutURIsSlice = []string{}
	}
	postLogoutURIs, _ := json.Marshal(postLogoutURIsSlice)

	finalGrantTypes := req.GrantTypes
	if finalGrantTypes == nil {
		finalGrantTypes = []string{"authorization_code"}
	}
	grantTypes, _ := json.Marshal(finalGrantTypes)

	finalResponseTypes := req.ResponseTypes
	if finalResponseTypes == nil {
		finalResponseTypes = []string{"code"}
	}
	responseTypes, _ := json.Marshal(finalResponseTypes)

	clientType := "confidential"
	if req.ClientType != "" {
		clientType = req.ClientType
	}
	scopes := "openid profile email"
	if req.Scopes != "" {
		scopes = req.Scopes
	}
	authMethod := "client_secret_basic"
	if req.TokenEndpointAuthMethod != "" {
		authMethod = req.TokenEndpointAuthMethod
	} else if clientType == "public" {
		authMethod = "none"
	}

	var audiences *string
	if req.AllowedAudiences != nil {
		b, _ := json.Marshal(req.AllowedAudiences)
		s := string(b)
		audiences = &s
	}

	id, _ := authcode.GenerateSecureCode()

	query := `
		INSERT INTO clients (
			id, client_id, client_secret, client_name, client_type, redirect_uris, 
			post_logout_redirect_uris, grant_types, response_types, scopes, 
			token_endpoint_auth_method, access_token_expiration, refresh_token_expiration,
			authorization_code_expiration, allowed_audiences, allow_self_signup,
			sso_session_idle_timeout, trust_device_enabled, trust_device_expiration
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := db.GetDB().Exec(query,
		id, clientID, hashedSecret, req.ClientName, clientType, string(redirectURIs),
		string(postLogoutURIs), string(grantTypes), string(responseTypes), scopes,
		authMethod, req.AccessTokenExpiration, req.RefreshTokenExpiration,
		req.AuthorizationCodeExpiration, audiences, req.AllowSelfSignup,
		req.SsoSessionIdleTimeout, req.TrustDeviceEnabled, req.TrustDeviceExpiration,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	return &ClientResponse{
		ClientID:                clientID,
		ClientSecret:            clientSecret,
		ClientSecretExpiresAt:   0,
		ClientName:              req.ClientName,
		ClientType:              clientType,
		RedirectURIs:            req.RedirectURIs,
		PostLogoutRedirectURIs:  postLogoutURIsSlice,
		GrantTypes:              finalGrantTypes,
		ResponseTypes:           finalResponseTypes,
		Scopes:                  scopes,
		TokenEndpointAuthMethod: authMethod,
	}, nil
}
