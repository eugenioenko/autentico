package client

import (
	"encoding/json"
	"fmt"

	"github.com/eugenioenko/autentico/pkg/db"
)

// resolveOptional returns the new override value: the request's value or null if it was present,
// otherwise the current stored value.
func resolveOptional[T any](o Optional[T], current *T) *T {
	if o.Set {
		return o.Value
	}
	return current
}

func UpdateClient(clientID string, req ClientUpdateRequest) error {
	// Get existing client to preserve values
	c, err := ClientByClientIDIncludingDisabled(clientID)
	if err != nil {
		return err
	}

	newName := c.ClientName
	if req.ClientName != "" {
		newName = req.ClientName
	}

	newRedirectURIs := c.RedirectURIs
	if req.RedirectURIs != nil {
		b, _ := json.Marshal(req.RedirectURIs)
		newRedirectURIs = string(b)
	}

	newPostLogoutRedirectURIs := c.PostLogoutRedirectURIs
	if req.PostLogoutRedirectURIs != nil {
		b, _ := json.Marshal(req.PostLogoutRedirectURIs)
		newPostLogoutRedirectURIs = string(b)
	}

	newGrantTypes := c.GrantTypes
	if req.GrantTypes != nil {
		b, _ := json.Marshal(req.GrantTypes)
		newGrantTypes = string(b)
	}

	newResponseTypes := c.ResponseTypes
	if req.ResponseTypes != nil {
		b, _ := json.Marshal(req.ResponseTypes)
		newResponseTypes = string(b)
	}

	newScopes := c.Scopes
	if req.Scopes != "" {
		newScopes = req.Scopes
	}

	// RFC 7591 §3.2.1: preserve effective secret requirements for legacy rows.
	newAuthMethod := c.effectiveTokenEndpointAuthMethod()
	if req.TokenEndpointAuthMethod != "" {
		newAuthMethod = req.TokenEndpointAuthMethod
	}

	// RFC 7591 §2 / §3.2.2: updates cannot contradict the immutable client type.
	_, newAuthMethod, err = resolveClientAuthentication(c.ClientType, newAuthMethod)
	if err != nil {
		return err
	}

	newIsActive := c.IsActive
	if req.IsActive != nil {
		newIsActive = *req.IsActive
	}

	var audiences *string
	if req.AllowedAudiences != nil {
		b, _ := json.Marshal(req.AllowedAudiences)
		s := string(b)
		audiences = &s
	} else {
		audiences = c.AllowedAudiences
	}

	newConsentRequired := c.ConsentRequired
	if req.ConsentRequired != nil {
		newConsentRequired = req.ConsentRequired
	}

	newDescription := c.Description
	if req.Description != nil {
		newDescription = *req.Description
	}

	newLogoURI := c.LogoURI
	if req.LogoURI != nil {
		newLogoURI = *req.LogoURI
	}

	newClientURI := c.ClientURI
	if req.ClientURI != nil {
		newClientURI = *req.ClientURI
	}

	newShowInAccount := c.ShowInAccount
	if req.ShowInAccount != nil {
		newShowInAccount = *req.ShowInAccount
	}

	// Per-client overrides: omitted keeps the stored value; null clears it (NULL inherits global); a value sets it.
	accessTokenExpiration := resolveOptional(req.AccessTokenExpiration, c.AccessTokenExpiration)
	refreshTokenExpiration := resolveOptional(req.RefreshTokenExpiration, c.RefreshTokenExpiration)
	authorizationCodeExpiration := resolveOptional(req.AuthorizationCodeExpiration, c.AuthorizationCodeExpiration)
	allowSelfSignup := resolveOptional(req.AllowSelfSignup, c.AllowSelfSignup)
	ssoSessionIdleTimeout := resolveOptional(req.SsoSessionIdleTimeout, c.SsoSessionIdleTimeout)
	trustDeviceEnabled := resolveOptional(req.TrustDeviceEnabled, c.TrustDeviceEnabled)
	trustDeviceExpiration := resolveOptional(req.TrustDeviceExpiration, c.TrustDeviceExpiration)

	access := accessUpdate{restrict: req.RestrictAccess, groups: req.AllowedGroups, users: req.AllowedUsers}
	if err := validateAccessUpdate(access); err != nil {
		return err
	}

	query := `
		UPDATE clients SET
			client_name = ?,
			redirect_uris = ?,
			post_logout_redirect_uris = ?,
			grant_types = ?,
			response_types = ?,
			scopes = ?,
			token_endpoint_auth_method = ?,
			is_active = ?,
			access_token_expiration = ?,
			refresh_token_expiration = ?,
			authorization_code_expiration = ?,
			allowed_audiences = ?,
			allow_self_signup = ?,
			sso_session_idle_timeout = ?,
			trust_device_enabled = ?,
			trust_device_expiration = ?,
			consent_required = ?,
			description = ?,
			logo_uri = ?,
			client_uri = ?,
			show_in_account = ?,
			updated_at = CURRENT_TIMESTAMP
		WHERE client_id = ?`
	tx, err := db.GetDB().Begin()
	if err != nil {
		return fmt.Errorf("failed to update client: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	_, err = tx.Exec(query,
		newName, newRedirectURIs, newPostLogoutRedirectURIs, newGrantTypes,
		newResponseTypes, newScopes, newAuthMethod, newIsActive,
		accessTokenExpiration, refreshTokenExpiration,
		authorizationCodeExpiration, audiences, allowSelfSignup,
		ssoSessionIdleTimeout, trustDeviceEnabled, trustDeviceExpiration,
		newConsentRequired,
		newDescription, newLogoURI, newClientURI, newShowInAccount,
		clientID,
	)
	if err != nil {
		return fmt.Errorf("failed to update client: %v", err)
	}
	if err := writeAccess(tx, clientID, access); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to update client: %v", err)
	}
	return nil
}
