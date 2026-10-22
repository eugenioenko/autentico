package client

import (
	"errors"
	"fmt"
)

// ErrInvalidClientMetadata identifies authentication metadata the server cannot
// register consistently (RFC 7591 §3.2.2).
var ErrInvalidClientMetadata = errors.New("invalid client authentication metadata")

// resolveClientAuthentication applies RFC 7591 §2 defaults before issuing any
// secret. The client_type extension must agree with the standard auth method.
func resolveClientAuthentication(clientType, method string) (string, string, error) {
	if clientType == "" {
		clientType = "confidential"
		if method == "none" {
			clientType = "public"
		}
	}
	// RFC 7591 §2 / RFC 6749 §2.1: only implemented client types are supported.
	if clientType != "public" && clientType != "confidential" {
		return "", "", fmt.Errorf("%w: client_type must be public or confidential", ErrInvalidClientMetadata)
	}
	if method == "" {
		method = "client_secret_basic"
		if clientType == "public" {
			method = "none"
		}
	}
	// RFC 7591 §2 / §3.2.2: reject unsupported authentication methods.
	if method != "none" && method != "client_secret_basic" && method != "client_secret_post" {
		return "", "", fmt.Errorf("%w: unsupported token_endpoint_auth_method", ErrInvalidClientMetadata)
	}
	// RFC 7591 §2: none identifies a public client without a client secret.
	if (clientType == "public") != (method == "none") {
		return "", "", fmt.Errorf("%w: token_endpoint_auth_method must be none for public clients and a client-secret method for confidential clients", ErrInvalidClientMetadata)
	}
	// RFC 7591 §3.2.1: return the effective metadata used for registration.
	return clientType, method, nil
}

// effectiveTokenEndpointAuthMethod reports existing authentication requirements
// for legacy contradictory registrations (RFC 7591 §3.2.1). ClientType remains
// authoritative: reporting none must never remove a confidential client's secret.
func (c *Client) effectiveTokenEndpointAuthMethod() string {
	if c.ClientType == "public" {
		return "none"
	}
	if c.TokenEndpointAuthMethod == "" || c.TokenEndpointAuthMethod == "none" {
		return "client_secret_basic"
	}
	return c.TokenEndpointAuthMethod
}
