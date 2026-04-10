// Package authzsig provides HMAC-SHA256 signing and verification for OAuth2
// authorize request parameters. This prevents tampering with hidden form fields
// (scope, code_challenge, code_challenge_method, nonce) between the authorize
// and login/signup steps.
package authzsig

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strings"

	"github.com/eugenioenko/autentico/pkg/config"
)

// AuthorizeParams holds the security-sensitive parameters from the authorize
// request that must be protected against tampering.
type AuthorizeParams struct {
	ClientID            string
	RedirectURI         string
	Scope               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	State               string
}

// Sign computes an HMAC-SHA256 signature over the authorize parameters using
// the CSRF secret key. The signature is returned as a base64url-encoded string.
func Sign(p AuthorizeParams) string {
	data := canonicalize(p)
	secret := []byte(config.GetBootstrap().AuthCSRFProtectionSecretKey)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Verify checks that the provided signature matches the HMAC of the given
// authorize parameters. Returns true if valid, false if tampered.
func Verify(p AuthorizeParams, signature string) bool {
	expected := Sign(p)
	return hmac.Equal([]byte(expected), []byte(signature))
}

// canonicalize builds a deterministic string from the authorize parameters.
// Fields are joined with a delimiter that cannot appear in valid OAuth2 values.
func canonicalize(p AuthorizeParams) string {
	return strings.Join([]string{
		p.ClientID,
		p.RedirectURI,
		p.Scope,
		p.Nonce,
		p.CodeChallenge,
		p.CodeChallengeMethod,
		p.State,
	}, "\n")
}
