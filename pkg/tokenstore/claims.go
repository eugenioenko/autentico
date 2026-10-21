// Package tokenstore contains the credential storage primitives used by
// token issuance and database lookups. It has no application or database dependencies.
package tokenstore

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// Metadata contains claims retained alongside an access token hash.
type Metadata struct {
	jwt.RegisteredClaims
	ClientID string `json:"azp"`
	ACR      string `json:"acr"`
}

// ReadIssuedMetadata extracts claims from an access JWT issued by this server.
// It does not verify signatures and must never authenticate an HTTP credential.
func ReadIssuedMetadata(raw string) (*Metadata, error) {
	claims := &Metadata{}
	parser := jwt.NewParser()
	token, parts, err := parser.ParseUnverified(raw, claims)
	if err != nil {
		return nil, fmt.Errorf("malformed issued JWT: %w", err)
	}
	if token.Method.Alg() != "RS256" {
		return nil, fmt.Errorf("unexpected issued JWT algorithm")
	}
	signature, err := parser.DecodeSegment(parts[2])
	if err != nil || len(signature) == 0 {
		return nil, fmt.Errorf("malformed issued JWT signature")
	}
	return claims, nil
}
