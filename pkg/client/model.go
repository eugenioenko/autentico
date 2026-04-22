package client

import (
	"encoding/json"
	"fmt"
	"time"

	"regexp"

	"github.com/eugenioenko/autentico/pkg/config"
	validation "github.com/go-ozzo/ozzo-validation"
	"github.com/go-ozzo/ozzo-validation/is"
)

// noHTMLPattern rejects strings containing HTML tag characters as defense-in-depth
// against stored XSS in fields that may be rendered in UI contexts.
var noHTMLPattern = regexp.MustCompile(`^[^<>]*$`)

// Client represents an OAuth2/OIDC client in the database
type Client struct {
	ID                      string    `db:"id"`
	ClientID                string    `db:"client_id"`
	ClientSecret            string    `db:"client_secret"`
	ClientName              string    `db:"client_name"`
	ClientType              string    `db:"client_type"`
	RedirectURIs            string    `db:"redirect_uris"`
	PostLogoutRedirectURIs  string    `db:"post_logout_redirect_uris"`
	GrantTypes              string    `db:"grant_types"`
	ResponseTypes           string    `db:"response_types"`
	Scopes                  string    `db:"scopes"`
	TokenEndpointAuthMethod string    `db:"token_endpoint_auth_method"`
	IsActive                bool      `db:"is_active"`
	CreatedAt               time.Time `db:"created_at"`
	UpdatedAt               time.Time `db:"updated_at"`
	// Per-client overrides — nil means "use global setting"
	AccessTokenExpiration       *string `db:"access_token_expiration"`
	RefreshTokenExpiration      *string `db:"refresh_token_expiration"`
	AuthorizationCodeExpiration *string `db:"authorization_code_expiration"`
	AllowedAudiences            *string `db:"allowed_audiences"` // JSON array
	AllowSelfSignup             *bool   `db:"allow_self_signup"`
	SsoSessionIdleTimeout       *string `db:"sso_session_idle_timeout"`
	TrustDeviceEnabled          *bool   `db:"trust_device_enabled"`
	TrustDeviceExpiration       *string `db:"trust_device_expiration"`
	// IsAdminServiceAccount, when true, allows client_credentials tokens issued
	// to this client to satisfy the admin-API authorization check without a user.
	// Only valid on confidential clients with the client_credentials grant enabled.
	IsAdminServiceAccount bool `db:"is_admin_service_account"`
}

// ClientCreateRequest represents the request body for client registration
type ClientCreateRequest struct {
	ClientID                string   `json:"client_id,omitempty"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	PostLogoutRedirectURIs  []string `json:"post_logout_redirect_uris,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	ClientType              string   `json:"client_type,omitempty"`
	Scopes                  string   `json:"scopes,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	// Per-client overrides
	AccessTokenExpiration       *string  `json:"access_token_expiration,omitempty"`
	RefreshTokenExpiration      *string  `json:"refresh_token_expiration,omitempty"`
	AuthorizationCodeExpiration *string  `json:"authorization_code_expiration,omitempty"`
	AllowedAudiences            []string `json:"allowed_audiences,omitempty"`
	AllowSelfSignup             *bool    `json:"allow_self_signup,omitempty"`
	SsoSessionIdleTimeout       *string  `json:"sso_session_idle_timeout,omitempty"`
	TrustDeviceEnabled          *bool    `json:"trust_device_enabled,omitempty"`
	TrustDeviceExpiration       *string  `json:"trust_device_expiration,omitempty"`
	// Elevates client_credentials tokens to admin-API access. Requires
	// client_type=confidential and grant_types containing "client_credentials".
	IsAdminServiceAccount *bool `json:"is_admin_service_account,omitempty"`
}

// ClientUpdateRequest represents the request body for updating a client
type ClientUpdateRequest struct {
	ClientName              string   `json:"client_name,omitempty"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	PostLogoutRedirectURIs  []string `json:"post_logout_redirect_uris,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	Scopes                  string   `json:"scopes,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	IsActive                *bool    `json:"is_active,omitempty"`
	// Per-client overrides
	AccessTokenExpiration       *string  `json:"access_token_expiration,omitempty"`
	RefreshTokenExpiration      *string  `json:"refresh_token_expiration,omitempty"`
	AuthorizationCodeExpiration *string  `json:"authorization_code_expiration,omitempty"`
	AllowedAudiences            []string `json:"allowed_audiences,omitempty"`
	AllowSelfSignup             *bool    `json:"allow_self_signup,omitempty"`
	SsoSessionIdleTimeout       *string  `json:"sso_session_idle_timeout,omitempty"`
	TrustDeviceEnabled          *bool    `json:"trust_device_enabled,omitempty"`
	TrustDeviceExpiration       *string  `json:"trust_device_expiration,omitempty"`
	// Elevates client_credentials tokens to admin-API access. See ClientCreateRequest.
	IsAdminServiceAccount *bool `json:"is_admin_service_account,omitempty"`
}

// ClientResponse represents the response for client operations
// ClientResponse is the registration response per RFC 7591 §3.2.1.
// The server MUST return all registered metadata about this client.
type ClientResponse struct {
	// RFC 7591 §3.2.1: client_id is REQUIRED.
	ClientID string `json:"client_id"`
	// RFC 7591 §3.2.1: client_secret is OPTIONAL (issued for confidential clients).
	ClientSecret string `json:"client_secret,omitempty"`
	// RFC 7591 §3.2.1: REQUIRED if client_secret is issued. 0 means no expiration.
	ClientSecretExpiresAt int `json:"client_secret_expires_at"`
	// RFC 7591 §3.2.1: OPTIONAL. Time at which the client_id was issued (Unix timestamp).
	ClientIDIssuedAt int64 `json:"client_id_issued_at"`

	ClientName              string   `json:"client_name"`
	ClientType              string   `json:"client_type"`
	RedirectURIs            []string `json:"redirect_uris"`
	PostLogoutRedirectURIs  []string `json:"post_logout_redirect_uris"`
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
	PostLogoutRedirectURIs  []string `json:"post_logout_redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	Scopes                  string   `json:"scopes"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	IsActive                bool     `json:"is_active"`
	// Per-client overrides
	AccessTokenExpiration       *string  `json:"access_token_expiration,omitempty"`
	RefreshTokenExpiration      *string  `json:"refresh_token_expiration,omitempty"`
	AuthorizationCodeExpiration *string  `json:"authorization_code_expiration,omitempty"`
	AllowedAudiences            []string `json:"allowed_audiences,omitempty"`
	AllowSelfSignup             *bool    `json:"allow_self_signup,omitempty"`
	SsoSessionIdleTimeout       *string  `json:"sso_session_idle_timeout,omitempty"`
	TrustDeviceEnabled          *bool    `json:"trust_device_enabled,omitempty"`
	TrustDeviceExpiration       *string  `json:"trust_device_expiration,omitempty"`
	IsAdminServiceAccount       bool     `json:"is_admin_service_account"`
}

// GetRedirectURIs parses and returns the redirect URIs as a slice
func (c *Client) GetRedirectURIs() []string {
	var uris []string
	_ = json.Unmarshal([]byte(c.RedirectURIs), &uris)
	return uris
}

// GetPostLogoutRedirectURIs parses and returns the post-logout redirect URIs as a slice
func (c *Client) GetPostLogoutRedirectURIs() []string {
	var uris []string
	if c.PostLogoutRedirectURIs == "" {
		return []string{}
	}
	_ = json.Unmarshal([]byte(c.PostLogoutRedirectURIs), &uris)
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
	resp := &ClientInfoResponse{
		ClientID:                c.ClientID,
		ClientName:              c.ClientName,
		ClientType:              c.ClientType,
		RedirectURIs:            c.GetRedirectURIs(),
		PostLogoutRedirectURIs:  c.GetPostLogoutRedirectURIs(),
		GrantTypes:              c.GetGrantTypes(),
		ResponseTypes:           c.GetResponseTypes(),
		Scopes:                  c.Scopes,
		TokenEndpointAuthMethod: c.TokenEndpointAuthMethod,
		IsActive:                c.IsActive,
		AccessTokenExpiration:       c.AccessTokenExpiration,
		RefreshTokenExpiration:      c.RefreshTokenExpiration,
		AuthorizationCodeExpiration: c.AuthorizationCodeExpiration,
		AllowSelfSignup:             c.AllowSelfSignup,
		SsoSessionIdleTimeout:       c.SsoSessionIdleTimeout,
		TrustDeviceEnabled:          c.TrustDeviceEnabled,
		TrustDeviceExpiration:       c.TrustDeviceExpiration,
		IsAdminServiceAccount:       c.IsAdminServiceAccount,
	}
	if c.AllowedAudiences != nil {
		var aud []string
		if err := json.Unmarshal([]byte(*c.AllowedAudiences), &aud); err == nil {
			resp.AllowedAudiences = aud
		}
	}
	return resp
}

// ToOverrides converts the nullable client override fields into a config.ClientOverrides
// struct, which can be passed to config.GetForClient() to resolve per-client settings.
func (c *Client) ToOverrides() config.ClientOverrides {
	overrides := config.ClientOverrides{
		AccessTokenExpiration:       c.AccessTokenExpiration,
		RefreshTokenExpiration:      c.RefreshTokenExpiration,
		AuthorizationCodeExpiration: c.AuthorizationCodeExpiration,
		AllowSelfSignup:             c.AllowSelfSignup,
		SsoSessionIdleTimeout:       c.SsoSessionIdleTimeout,
		TrustDeviceEnabled:          c.TrustDeviceEnabled,
		TrustDeviceExpiration:       c.TrustDeviceExpiration,
	}
	if c.AllowedAudiences != nil {
		var aud []string
		if err := json.Unmarshal([]byte(*c.AllowedAudiences), &aud); err == nil {
			overrides.AllowedAudiences = aud
		}
	}
	return overrides
}

// ValidateClientCreateRequest validates a client registration request
func ValidateClientCreateRequest(input ClientCreateRequest) error {
	if err := validation.ValidateStruct(&input,
		validation.Field(&input.ClientName, validation.Required, validation.Length(1, 255), validation.Match(noHTMLPattern).Error("must not contain HTML characters (< or >)")),
		validation.Field(&input.RedirectURIs, validation.Required, validation.Length(1, 10)),
		validation.Field(&input.GrantTypes, validation.Each(validation.In("authorization_code", "refresh_token", "client_credentials", "password"))),
		validation.Field(&input.ResponseTypes, validation.Each(validation.In("code", "token", "id_token"))),
		validation.Field(&input.ClientType, validation.In("", "confidential", "public")),
		validation.Field(&input.TokenEndpointAuthMethod, validation.In("", "client_secret_basic", "client_secret_post", "none")),
	); err != nil {
		return err
	}
	if input.IsAdminServiceAccount != nil && *input.IsAdminServiceAccount {
		if err := validateAdminServiceAccount(input.ClientType, input.GrantTypes); err != nil {
			return err
		}
	}
	return nil
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
		validation.Field(&input.ClientName, validation.Length(0, 255), validation.Match(noHTMLPattern).Error("must not contain HTML characters (< or >)")),
		validation.Field(&input.RedirectURIs, validation.Length(0, 10)),
		validation.Field(&input.GrantTypes, validation.Each(validation.In("authorization_code", "refresh_token", "client_credentials", "password"))),
		validation.Field(&input.ResponseTypes, validation.Each(validation.In("code", "token", "id_token"))),
		validation.Field(&input.TokenEndpointAuthMethod, validation.In("", "client_secret_basic", "client_secret_post", "none")),
	)
}

// validateAdminServiceAccount enforces that a client flagged as an admin
// service account is confidential and has the client_credentials grant enabled.
// effectiveClientType is "" when the caller did not specify one — in that
// case the server default ("confidential") applies and validation passes.
func validateAdminServiceAccount(effectiveClientType string, grantTypes []string) error {
	if effectiveClientType == "public" {
		return fmt.Errorf("is_admin_service_account requires client_type=confidential")
	}
	for _, g := range grantTypes {
		if g == "client_credentials" {
			return nil
		}
	}
	return fmt.Errorf("is_admin_service_account requires grant_types to include client_credentials")
}
