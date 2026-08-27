package userclaim

import (
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	validation "github.com/go-ozzo/ozzo-validation"
)

// claimNameRegex allows bare names (tier, employee_id) and collision-resistant
// namespaced names (https://app.example.com/tier). OIDC Core §5.1.2 RECOMMENDS
// collision-resistant or private claim names for non-standard claims.
var claimNameRegex = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.:/-]*$`)

const maxClaimValueLength = 4096

// reservedClaimNames are claim names a custom claim must never define. OIDC Core
// §5.1.2 / RFC 9068 §2.2.2: additional claims must not collide with standard
// claims. This is the IANA "JSON Web Token Claims" registry (identity, security,
// and authorization claims) — a relying party or resource server may trust any of
// these, so an admin must not be able to forge one. The token builder's "never
// override an existing claim" guard is not enough on its own: Autentico does not
// emit most of these, so nothing would stop the forged value from being signed.
//
// Transport-specific registry entries (SIP RFC 8055/8443, CDNI RFC 9246) are
// omitted as irrelevant to this IdP. Keep this in sync with the registry:
// https://www.iana.org/assignments/jwt/jwt.xhtml
var reservedClaimNames = map[string]bool{
	// RFC 7519 — registered claim names
	"iss": true, "sub": true, "aud": true, "exp": true, "nbf": true, "iat": true, "jti": true,
	// OIDC Core 1.0 — ID token / authentication claims
	"auth_time": true, "nonce": true, "acr": true, "amr": true, "azp": true,
	"at_hash": true, "c_hash": true, "sub_jwk": true,
	// OIDC Core 1.0 §5.1 — standard profile / email / phone / address claims
	"name": true, "given_name": true, "family_name": true, "middle_name": true,
	"nickname": true, "preferred_username": true, "profile": true, "picture": true,
	"website": true, "email": true, "email_verified": true, "gender": true,
	"birthdate": true, "zoneinfo": true, "locale": true, "phone_number": true,
	"phone_number_verified": true, "address": true, "updated_at": true,
	// OIDC aggregated / distributed claims
	"_claim_names": true, "_claim_sources": true,
	// OIDC session management / logout (RFC 8471, OIDC BCL/FCL)
	"sid": true, "events": true,
	// OIDC Identity Assurance 1.0
	"verified_claims": true, "place_of_birth": true, "nationalities": true,
	"birth_family_name": true, "birth_given_name": true, "birth_middle_name": true,
	"salutation": true, "title": true, "msisdn": true, "also_known_as": true,
	// RFC 9068 JWT access tokens / RFC 7643 SCIM — authorization attributes
	"client_id": true, "scope": true, "roles": true, "groups": true, "entitlements": true,
	// RFC 8693 — OAuth 2.0 Token Exchange
	"act": true, "may_act": true,
	// RFC 7800 / RFC 9449 — proof-of-possession & DPoP
	"cnf": true, "htm": true, "htu": true, "ath": true, "jkt": true,
	// RFC 9396 — Rich Authorization Requests
	"authorization_details": true,
	// RFC 8417 — Security Event Token / RFC 9493 — Subject Identifiers
	"toe": true, "txn": true, "sub_id": true,
	// SD-JWT — selective disclosure
	"_sd": true, "_sd_alg": true, "sd_hash": true,
	// W3C Verifiable Credentials
	"vc": true, "vp": true,
	// RFC 8485 — Vectors of Trust
	"vot": true, "vtm": true,
	// Claims Autentico itself emits that are not in the registry above
	"typ": true, "token_type": true, "active": true, "role": true,
}

// UserClaim is a single custom claim attached to a user.
type UserClaim struct {
	UserID    string
	Name      string
	Value     string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// UserClaimResponse is the admin API representation of a custom claim.
type UserClaimResponse struct {
	Name      string    `json:"name"`
	Value     string    `json:"value"`
	UpdatedAt time.Time `json:"updated_at"`
}

// UserClaimRequest is the admin API payload for creating or updating a claim.
type UserClaimRequest struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// IsReservedClaimName reports whether name collides with a registered JWT/OIDC
// claim and therefore may not be used as a custom claim name.
func IsReservedClaimName(name string) bool {
	return reservedClaimNames[strings.ToLower(strings.TrimSpace(name))]
}

// ValidateUserClaimRequest validates a custom claim create/update payload.
func ValidateUserClaimRequest(input UserClaimRequest) error {
	if err := validation.Validate(input.Name,
		validation.Required,
		validation.Length(1, 128),
		validation.Match(claimNameRegex),
	); err != nil {
		return fmt.Errorf("name is invalid: %w", err)
	}
	if IsReservedClaimName(input.Name) {
		return fmt.Errorf("name is invalid: %q is a reserved claim name", input.Name)
	}
	if utf8.RuneCountInString(input.Value) > maxClaimValueLength {
		return fmt.Errorf("value is invalid: must be at most %d characters", maxClaimValueLength)
	}
	return nil
}
