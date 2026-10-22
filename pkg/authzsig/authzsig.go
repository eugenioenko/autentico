// Package authzsig provides HMAC-SHA256 signing and verification for OAuth2
// authorize request parameters. This prevents tampering with hidden form fields
// (scope, code_challenge, code_challenge_method, nonce) between the authorize
// and login/signup steps.
package authzsig

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
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
	Prompt              string
	MaxAge              string
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
// Controlled requests use unambiguous encoding; ordinary requests retain the
// original format so already-issued email links continue to verify.
func canonicalize(p AuthorizeParams) string {
	// OIDC Core §3.1.2.1: prompts and freshness controls cannot be removed
	// or relaxed between authorization and primary authentication. Preserve
	// signatures on older ordinary links that did not carry these controls.
	if p.Prompt != "" || p.MaxAge != "" {
		return "authorize-controls-v2\n" + url.Values{
			"client_id": {p.ClientID}, "redirect_uri": {p.RedirectURI}, "scope": {p.Scope},
			"state": {p.State}, "nonce": {p.Nonce}, "code_challenge": {p.CodeChallenge},
			"code_challenge_method": {p.CodeChallengeMethod}, "prompt": {p.Prompt}, "max_age": {p.MaxAge},
		}.Encode()
	}
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

// FromValues reads the signed fields without normalizing their contents.
func FromValues(v url.Values) AuthorizeParams {
	return AuthorizeParams{ClientID: v.Get("client_id"), RedirectURI: v.Get("redirect_uri"), Scope: v.Get("scope"),
		Nonce: v.Get("nonce"), CodeChallenge: v.Get("code_challenge"), CodeChallengeMethod: v.Get("code_challenge_method"), State: v.Get("state"),
		Prompt: v.Get("prompt"),
		MaxAge: v.Get("max_age"),
	}
}
