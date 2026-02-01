package client

import (
	"fmt"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

// AuthenticateClient verifies the client credentials
// Returns the client if authentication succeeds, error otherwise
func AuthenticateClient(clientID, clientSecret string) (*Client, error) {
	client, err := ClientByClientID(clientID)
	if err != nil {
		return nil, fmt.Errorf("invalid client credentials")
	}

	if !client.IsActive {
		return nil, fmt.Errorf("client is inactive")
	}

	// Public clients don't require secret verification
	if client.ClientType == "public" {
		return client, nil
	}

	// Confidential clients must provide a valid secret
	if clientSecret == "" {
		return nil, fmt.Errorf("client secret required for confidential clients")
	}

	err = bcrypt.CompareHashAndPassword([]byte(client.ClientSecret), []byte(clientSecret))
	if err != nil {
		return nil, fmt.Errorf("invalid client credentials")
	}

	return client, nil
}

// AuthenticateClientFromRequest extracts client credentials from the HTTP request
// and authenticates the client. Supports both Basic Auth and form parameters.
// Returns nil, nil if no client credentials are provided (backward compatibility)
func AuthenticateClientFromRequest(r *http.Request) (*Client, error) {
	// Try Basic Auth first (client_secret_basic)
	if user, pass, ok := r.BasicAuth(); ok {
		return AuthenticateClient(user, pass)
	}

	// Fall back to form params (client_secret_post)
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	if clientID != "" {
		// If client_id is provided, try to authenticate
		client, err := ClientByClientID(clientID)
		if err != nil {
			// Client not found - for backward compatibility, return nil
			// This allows flows without registered clients to continue working
			return nil, nil
		}

		// If client exists and is public, no secret needed
		if client.ClientType == "public" {
			if !client.IsActive {
				return nil, fmt.Errorf("client is inactive")
			}
			return client, nil
		}

		// Confidential client - verify secret
		if clientSecret == "" {
			return nil, fmt.Errorf("client secret required")
		}

		return AuthenticateClient(clientID, clientSecret)
	}

	// No client credentials provided - backward compatibility
	return nil, nil
}

// IsValidRedirectURI checks if the given redirect URI is allowed for the client
func IsValidRedirectURI(client *Client, redirectURI string) bool {
	if client == nil {
		return true // Backward compatibility when no client is registered
	}

	allowedURIs := client.GetRedirectURIs()
	for _, uri := range allowedURIs {
		if uri == redirectURI {
			return true
		}
	}
	return false
}

// IsGrantTypeAllowed checks if the given grant type is allowed for the client
func IsGrantTypeAllowed(client *Client, grantType string) bool {
	if client == nil {
		return true // Backward compatibility when no client is registered
	}

	allowedTypes := client.GetGrantTypes()
	for _, t := range allowedTypes {
		if t == grantType {
			return true
		}
	}
	return false
}

// IsResponseTypeAllowed checks if the given response type is allowed for the client
func IsResponseTypeAllowed(client *Client, responseType string) bool {
	if client == nil {
		return true // Backward compatibility when no client is registered
	}

	allowedTypes := client.GetResponseTypes()
	for _, t := range allowedTypes {
		if t == responseType {
			return true
		}
	}
	return false
}
