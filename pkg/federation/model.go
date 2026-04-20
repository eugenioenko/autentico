package federation

import (
	"database/sql"
	"time"
)

// FederationProvider represents a registered OIDC identity provider.
type FederationProvider struct {
	ID           string
	Name         string
	Issuer       string
	ClientID     string
	ClientSecret string
	IconSVG      sql.NullString
	Enabled      bool
	SortOrder    int
	CreatedAt    time.Time
}

// FederationProviderView is a safe, template-ready representation of a provider.
// HasIcon signals whether to emit an <img> referencing the icon route — admin SVG
// is never injected into the login HTML directly to prevent stored XSS.
type FederationProviderView struct {
	ID      string
	Name    string
	HasIcon bool
}

// FederatedIdentity links a local user to a provider-specific subject (sub).
type FederatedIdentity struct {
	ID             string
	ProviderID     string
	ProviderUserID string
	UserID         string
	Email          sql.NullString
	CreatedAt      time.Time
}

// FederationState is HMAC-signed and round-tripped via the OAuth2 state parameter.
// It carries the original OIDC authorization request params across the provider redirect.
type FederationState struct {
	Nonce               string `json:"nonce"`
	ProviderID          string `json:"provider_id"`
	RedirectURI         string `json:"redirect_uri"`
	ClientID            string `json:"client_id"`
	Scope               string `json:"scope"`
	State               string `json:"state"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}

// FederationProviderRequest is used for admin create/update API calls.
type FederationProviderRequest struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Issuer       string `json:"issuer"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	IconSVG      string `json:"icon_svg"`
	Enabled      *bool  `json:"enabled"`
	SortOrder    int    `json:"sort_order"`
}
