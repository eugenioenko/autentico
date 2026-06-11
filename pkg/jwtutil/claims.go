package jwtutil

import "github.com/golang-jwt/jwt/v5"

// ZeroClaims satisfies the jwt/v5 Claims getter interface with empty values.
// Embed it in a custom claims struct and override only the getters that carry
// validation policy (typically GetExpirationTime).
//
// Safe only because no parser passes WithIssuer/WithSubject/WithAudience
// options — issuer and audience checks are done explicitly after parsing
// (see ValidateAudience).
type ZeroClaims struct{}

func (ZeroClaims) GetExpirationTime() (*jwt.NumericDate, error) { return nil, nil }
func (ZeroClaims) GetIssuedAt() (*jwt.NumericDate, error)       { return nil, nil }
func (ZeroClaims) GetNotBefore() (*jwt.NumericDate, error)      { return nil, nil }
func (ZeroClaims) GetIssuer() (string, error)                   { return "", nil }
func (ZeroClaims) GetSubject() (string, error)                  { return "", nil }
func (ZeroClaims) GetAudience() (jwt.ClaimStrings, error)       { return nil, nil }
