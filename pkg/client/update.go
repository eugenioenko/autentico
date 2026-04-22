package client

import (
	"encoding/json"
	"fmt"

	"github.com/eugenioenko/autentico/pkg/db"
)

func UpdateClient(clientID string, req ClientUpdateRequest) error {
	// Get existing client to preserve values
	c, err := ClientByClientID(clientID)
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

	newAuthMethod := c.TokenEndpointAuthMethod
	if req.TokenEndpointAuthMethod != "" {
		newAuthMethod = req.TokenEndpointAuthMethod
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

	// Preserve the existing flag if the caller did not send one — an "update
	// client name" request must not silently flip or clear the service-account bit.
	newIsAdminServiceAccount := c.IsAdminServiceAccount
	if req.IsAdminServiceAccount != nil {
		newIsAdminServiceAccount = *req.IsAdminServiceAccount
	}

	// Defense-in-depth: recompute effective grant types + client type for the
	// resulting row and reject the update if it would leave a flagged client in
	// an invalid state (public or missing client_credentials).
	if newIsAdminServiceAccount {
		effectiveClientType := c.ClientType
		if effectiveClientType == "" {
			effectiveClientType = "confidential"
		}
		var effectiveGrantTypes []string
		if req.GrantTypes != nil {
			effectiveGrantTypes = req.GrantTypes
		} else {
			effectiveGrantTypes = c.GetGrantTypes()
		}
		if err := validateAdminServiceAccount(effectiveClientType, effectiveGrantTypes); err != nil {
			return err
		}
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
			is_admin_service_account = ?,
			updated_at = CURRENT_TIMESTAMP
		WHERE client_id = ?`
	_, err = db.GetDB().Exec(query,
		newName, newRedirectURIs, newPostLogoutRedirectURIs, newGrantTypes,
		newResponseTypes, newScopes, newAuthMethod, newIsActive,
		req.AccessTokenExpiration, req.RefreshTokenExpiration,
		req.AuthorizationCodeExpiration, audiences, req.AllowSelfSignup,
		req.SsoSessionIdleTimeout, req.TrustDeviceEnabled, req.TrustDeviceExpiration,
		newIsAdminServiceAccount,
		clientID,
	)
	if err != nil {
		return fmt.Errorf("failed to update client: %v", err)
	}
	return nil
}
