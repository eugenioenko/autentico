package client

import (
	"fmt"
	"net/url"

	"github.com/eugenioenko/autentico/pkg/authzsig"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// ValidateAuthorization checks a code request against the current registration.
// A signed request proves integrity; it never replaces these authorization checks.
func ValidateAuthorization(p authzsig.AuthorizeParams) (*Client, error) {
	// RFC 6749 §4.1.1 / §4.1.2.1: never authorize an unidentified client.
	if p.ClientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}
	c, err := ClientByClientID(p.ClientID)
	if err != nil || !c.IsActive {
		return nil, fmt.Errorf("unknown or inactive client")
	}
	// OIDC Core §3.1.2.1: malformed controls must not disable authentication.
	if _, err := ParseMaxAge(p.MaxAge); err != nil {
		return nil, err
	}
	if err := ValidatePrompt(p.Prompt); err != nil {
		return nil, err
	}
	// RFC 6749 §3.1.2 / §10.6: require an allowed URI without a fragment.
	u, err := url.Parse(p.RedirectURI)
	if err != nil || !utils.IsValidRedirectURI(p.RedirectURI) || u.Fragment != "" || !IsValidRedirectURI(c, p.RedirectURI) {
		return nil, fmt.Errorf("redirect_uri is not allowed for this client")
	}
	// RFC 6749 §4.1.2.1: the client must be authorized for the code flow.
	if !IsGrantTypeAllowed(c, "authorization_code") || !IsResponseTypeAllowed(c, "code") {
		return nil, fmt.Errorf("authorization code flow is not allowed for this client")
	}
	// RFC 6749 §3.3: scope tokens contain printable ASCII excluding quote and backslash.
	for _, ch := range p.Scope {
		if ch < 0x20 || ch > 0x7e || ch == '"' || ch == '\\' {
			return nil, fmt.Errorf("invalid scope syntax")
		}
	}
	// RFC 6749 §3.3 / §4.1.2.1: reject scopes outside the client's allowlist.
	if !ValidateScopes(c, p.Scope) {
		return nil, fmt.Errorf("scope is not allowed for this client")
	}
	if err := ValidatePKCE(c.ClientType, p.CodeChallenge, p.CodeChallengeMethod); err != nil {
		return nil, err
	}
	return c, nil
}

// ValidatePKCE applies the same challenge and transformation policy before SSO
// and when completing any signed browser authorization flow.
func ValidatePKCE(clientType, challenge, method string) error {
	// RFC 9700 §2.1.1: public clients must use PKCE.
	if clientType == "public" && challenge == "" {
		return fmt.Errorf("code_challenge is required for public clients")
	}
	// RFC 7636 §4.3 / §4.4.1: reject unsupported or unbound transformations.
	if method != "" && (challenge == "" || (method != "S256" && method != "plain")) {
		return fmt.Errorf("invalid code_challenge_method")
	}
	// RFC 7636 §7.2: retain the configured S256 enforcement policy.
	if method == "plain" && config.Get().AuthPKCEEnforceSHA256 {
		return fmt.Errorf("code_challenge_method plain is not allowed; use S256")
	}
	return nil
}
