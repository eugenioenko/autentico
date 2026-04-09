package testutils

import (
	"net/url"

	"github.com/eugenioenko/autentico/pkg/authzsig"
)

// SetAuthorizeSig computes and sets the authorize_sig field on url.Values
// from the OAuth authorize parameters. Works for both form data and query params.
func SetAuthorizeSig(v url.Values) {
	v.Set("authorize_sig", authzsig.Sign(authzsig.AuthorizeParams{
		ClientID:            v.Get("client_id"),
		RedirectURI:         v.Get("redirect_uri"),
		Scope:               v.Get("scope"),
		Nonce:               v.Get("nonce"),
		CodeChallenge:       v.Get("code_challenge"),
		CodeChallengeMethod: v.Get("code_challenge_method"),
		State:               v.Get("state"),
	}))
}

// SignedURL appends an authorize_sig query param computed from the existing
// query params in the URL. Useful for passkey begin endpoints.
func SignedURL(rawURL string) string {
	u, _ := url.Parse(rawURL)
	q := u.Query()
	SetAuthorizeSig(q)
	u.RawQuery = q.Encode()
	return u.String()
}
