package client

import (
	"encoding/json"
	"time"

	validation "github.com/go-ozzo/ozzo-validation"
	"github.com/go-ozzo/ozzo-validation/is"
)

// Client represents an OAuth2/OIDC client in the database
type Client struct {
	ID                      string    `db:"id"`
	ClientID                string    `db:"client_id"`
	ClientSecret            string    `db:"client_secret"`
	ClientName              string    `db:"client_name"`
	ClientType              string    `db:"client_type"`
	RedirectURIs            string    `db:"redirect_uris"`
	GrantTypes              string    `db:"grant_types"`
	ResponseTypes           string    `db:"response_types"`
	Scopes                  string    `db:"scopes"`
	TokenEndpointAuthMethod string    `db:"token_endpoint_auth_method"`
	IsActive                bool      `db:"is_active"`
	CreatedAt               time.Time `db:"created_at"`
	UpdatedAt               time.Time `db:"updated_at"`
}

// ClientCreateRequest represents the request body for client registration
type ClientCreateRequest struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	ClientType              string   `json:"client_type,omitempty"`
	Scopes                  string   `json:"scopes,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
}

// ClientUpdateRequest represents the request body for updating a client
type ClientUpdateRequest struct {
	ClientName              string   `json:"client_name,omitempty"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	Scopes                  string   `json:"scopes,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	IsActive                *bool    `json:"is_active,omitempty"`
}

// ClientResponse represents the response for client operations
type ClientResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientSecretExpiresAt   int      `json:"client_secret_expires_at"`
	ClientName              string   `json:"client_name"`
	ClientType              string   `json:"client_type"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	Scopes                  string   `json:"scopes"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

// ClientInfoResponse represents the response for getting client info (without secret)
type ClientInfoResponse struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name"`
	ClientType              string   `json:"client_type"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	Scopes                  string   `json:"scopes"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	IsActive                bool     `json:"is_active"`
}

// GetRedirectURIs parses and returns the redirect URIs as a slice
func (c *Client) GetRedirectURIs() []string {
	var uris []string
	_ = json.Unmarshal([]byte(c.RedirectURIs), &uris)
	return uris
}

// GetGrantTypes parses and returns the grant types as a slice
func (c *Client) GetGrantTypes() []string {
	var types []string
	_ = json.Unmarshal([]byte(c.GrantTypes), &types)
	return types
}

// GetResponseTypes parses and returns the response types as a slice
func (c *Client) GetResponseTypes() []string {
	var types []string
	_ = json.Unmarshal([]byte(c.ResponseTypes), &types)
	return types
}

// ToInfoResponse converts a Client to a ClientInfoResponse
func (c *Client) ToInfoResponse() *ClientInfoResponse {
	return &ClientInfoResponse{
		ClientID:                c.ClientID,
		ClientName:              c.ClientName,
		ClientType:              c.ClientType,
		RedirectURIs:            c.GetRedirectURIs(),
		GrantTypes:              c.GetGrantTypes(),
		ResponseTypes:           c.GetResponseTypes(),
		Scopes:                  c.Scopes,
		TokenEndpointAuthMethod: c.TokenEndpointAuthMethod,
		IsActive:                c.IsActive,
	}
}

// ValidateClientCreateRequest validates a client registration request
func ValidateClientCreateRequest(input ClientCreateRequest) error {
	return validation.ValidateStruct(&input,
		validation.Field(&input.ClientName, validation.Required, validation.Length(1, 255)),
		validation.Field(&input.RedirectURIs, validation.Required, validation.Length(1, 10)),
		validation.Field(&input.GrantTypes, validation.Each(validation.In("authorization_code", "refresh_token", "client_credentials", "password"))),
		validation.Field(&input.ResponseTypes, validation.Each(validation.In("code", "token", "id_token"))),
		validation.Field(&input.ClientType, validation.In("", "confidential", "public")),
		validation.Field(&input.TokenEndpointAuthMethod, validation.In("", "client_secret_basic", "client_secret_post", "none")),
	)
}

// ValidateRedirectURIs validates that all redirect URIs are valid URLs
func ValidateRedirectURIs(uris []string) error {
	for _, uri := range uris {
		if err := validation.Validate(uri, validation.Required, is.URL); err != nil {
			return err
		}
	}
	return nil
}

// ValidateClientUpdateRequest validates a client update request
func ValidateClientUpdateRequest(input ClientUpdateRequest) error {
	return validation.ValidateStruct(&input,
		validation.Field(&input.ClientName, validation.Length(0, 255)),
		validation.Field(&input.RedirectURIs, validation.Length(0, 10)),
		validation.Field(&input.GrantTypes, validation.Each(validation.In("authorization_code", "refresh_token", "client_credentials", "password"))),
		validation.Field(&input.ResponseTypes, validation.Each(validation.In("code", "token", "id_token"))),
		validation.Field(&input.TokenEndpointAuthMethod, validation.In("", "client_secret_basic", "client_secret_post", "none")),
	)
}
