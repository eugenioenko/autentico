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

// reservedClaimNames are claim names a custom claim must never define: structural
// JWT/OIDC claims whose meaning is fixed, plus every claim Autentico already emits
// into its access tokens, ID tokens, or UserInfo responses. OIDC Core §5.1.2 /
// RFC 9068 §2.2.2: additional claims must not collide with standard claims.
//
// Known gap: this does not block registered claims that Autentico happens not to
// emit today (e.g. cnf, roles, entitlements, act). The token builder's
// "never override an existing claim" guard does not cover these because Autentico
// never sets them, so a relying party could treat an admin-set value as genuine.
// Tracked in issue #399.
var reservedClaimNames = map[string]bool{
	// Structural JWT / OIDC claims
	"iss": true, "sub": true, "aud": true, "exp": true, "iat": true, "nbf": true,
	"jti": true, "auth_time": true, "nonce": true, "at_hash": true, "c_hash": true,
	"azp": true, "sid": true, "acr": true, "amr": true, "typ": true, "scope": true,
	"client_id": true, "token_type": true, "active": true,
	// Claims Autentico already emits (see pkg/token/generate.go, pkg/userinfo/handler.go)
	"name": true, "preferred_username": true, "given_name": true, "family_name": true,
	"middle_name": true, "nickname": true, "profile": true, "picture": true,
	"website": true, "gender": true, "birthdate": true, "locale": true, "zoneinfo": true,
	"updated_at": true, "email": true, "email_verified": true, "phone_number": true,
	"phone_number_verified": true, "address": true, "groups": true, "role": true,
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

// IsReservedClaimName reports whether name collides with a standard/structural
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
