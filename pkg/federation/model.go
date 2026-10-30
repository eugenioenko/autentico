package federation

import (
	"database/sql"
	"time"

	"github.com/eugenioenko/autentico/pkg/authzsig"
)

// FederationProvider represents a registered OIDC identity provider.
type FederationProvider struct {
	ID                     string
	Name                   string
	Issuer                 string
	ClientID               string
	ClientSecret           string
	IconSVG                sql.NullString
	Enabled                bool
	SortOrder              int
	CreatedAt              time.Time
	ClaimRequirements      ClaimRequirements
	ClaimRequirementsError string
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
// FlowID binds the upstream nonce; Nonce remains the original RP nonce.
type FederationState struct {
	FlowID              string `json:"flow_id"`
	ExpiresAt           int64  `json:"exp"`
	Nonce               string `json:"nonce"`
	ProviderID          string `json:"provider_id"`
	RedirectURI         string `json:"redirect_uri"`
	ClientID            string `json:"client_id"`
	Scope               string `json:"scope"`
	State               string `json:"state"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	Prompt              string `json:"prompt,omitempty"`
	MaxAge              string `json:"max_age,omitempty"`
}

// FederationProviderRequest is used for admin create/update API calls.
type FederationProviderRequest struct {
	ClaimRequirements ClaimRequirements `json:"claim_requirements,omitzero"`
	ID                string            `json:"id"`
	Name              string            `json:"name"`
	Issuer            string            `json:"issuer"`
	ClientID          string            `json:"client_id"`
	ClientSecret      string            `json:"client_secret"`
	IconSVG           string            `json:"icon_svg"`
	Enabled           *bool             `json:"enabled"`
	SortOrder         int               `json:"sort_order"`
}

func (s *FederationState) authorizeParams() authzsig.AuthorizeParams {
	return authzsig.AuthorizeParams{ClientID: s.ClientID, RedirectURI: s.RedirectURI, Scope: s.Scope,
		Nonce: s.Nonce, State: s.State, CodeChallenge: s.CodeChallenge, CodeChallengeMethod: s.CodeChallengeMethod,
		Prompt: s.Prompt,
		MaxAge: s.MaxAge,
	}
}
