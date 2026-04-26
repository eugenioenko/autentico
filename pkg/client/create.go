package client

import (
	"encoding/json"
	"fmt"
	"time"

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

func CreateClientWithID(clientID string, req ClientCreateRequest) (*ClientResponse, error) {
	return createClientInternal(clientID, req)
}

func createClientInternal(clientID string, req ClientCreateRequest) (*ClientResponse, error) {
	issuedAt := time.Now().Unix()

	// RFC 7591 §3.2.1: client_secret OPTIONAL — issued for confidential clients.
	clientSecret := ""
	hashedSecret := ""
	if req.ClientType != "public" {
		if req.ClientSecret != "" {
			// Use the caller-provided secret
			clientSecret = req.ClientSecret
		} else {
			var err error
			clientSecret, err = authcode.GenerateSecureCode()
			if err != nil {
				return nil, fmt.Errorf("failed to generate client secret: %w", err)
			}
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

	// RFC 7591 §2: default grant_types is ["authorization_code"] when omitted.
	finalGrantTypes := req.GrantTypes
	if finalGrantTypes == nil {
		finalGrantTypes = []string{"authorization_code"}
	}
	grantTypes, _ := json.Marshal(finalGrantTypes)

	// RFC 7591 §2: default response_types is ["code"] when omitted.
	finalResponseTypes := req.ResponseTypes
	if finalResponseTypes == nil {
		finalResponseTypes = []string{"code"}
	}
	responseTypes, _ := json.Marshal(finalResponseTypes)

	clientType := "confidential"
	if req.ClientType != "" {
		clientType = req.ClientType
	}
	// RFC 7591 §2: scope — if omitted, server MAY register with a default set of scopes.
	scopes := "openid profile email"
	if req.Scopes != "" {
		scopes = req.Scopes
	}
	// RFC 7591 §2: default token_endpoint_auth_method is "client_secret_basic".
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
	_, err := db.GetWriteDB().Exec(query,
		id, clientID, hashedSecret, req.ClientName, clientType, string(redirectURIs),
		string(postLogoutURIs), string(grantTypes), string(responseTypes), scopes,
		authMethod, req.AccessTokenExpiration, req.RefreshTokenExpiration,
		req.AuthorizationCodeExpiration, audiences, req.AllowSelfSignup,
		req.SsoSessionIdleTimeout, req.TrustDeviceEnabled, req.TrustDeviceExpiration,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	// RFC 7591 §3.2.1: The server MUST return all registered metadata about this client.
	return &ClientResponse{
		ClientID:                clientID,
		ClientSecret:            clientSecret,
		ClientSecretExpiresAt:   0,
		ClientIDIssuedAt:        issuedAt,
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
