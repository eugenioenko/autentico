package client

import (
	"testing"

	"github.com/eugenioenko/autentico/pkg/authzsig"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestValidateAuthorization(t *testing.T) {
	for _, tc := range []struct {
		name       string
		change     func(*authzsig.AuthorizeParams)
		sql        string
		allowPlain bool
		valid      bool
	}{
		{name: "public PKCE", valid: true},
		{name: "default S256", valid: true, change: func(p *authzsig.AuthorizeParams) { p.CodeChallengeMethod = "" }},
		{name: "confidential without PKCE", valid: true, sql: "UPDATE clients SET client_type='confidential'", change: func(p *authzsig.AuthorizeParams) { p.CodeChallenge, p.CodeChallengeMethod = "", "" }},
		{name: "explicit plain opt-in", valid: true, allowPlain: true, change: func(p *authzsig.AuthorizeParams) { p.CodeChallengeMethod = "plain" }},
		{name: "missing client", change: func(p *authzsig.AuthorizeParams) { p.ClientID = "" }},
		{name: "unknown client", change: func(p *authzsig.AuthorizeParams) { p.ClientID = "unknown" }},
		{name: "inactive client", sql: "UPDATE clients SET is_active=FALSE"},
		{name: "missing redirect", change: func(p *authzsig.AuthorizeParams) { p.RedirectURI = "" }},
		{name: "malformed redirect", change: func(p *authzsig.AuthorizeParams) { p.RedirectURI = "://" }},
		{name: "unregistered redirect", change: func(p *authzsig.AuthorizeParams) { p.RedirectURI = "https://attacker.example/callback" }},
		{name: "fragment", sql: `UPDATE clients SET redirect_uris='["https://rp.example/callback#fragment"]'`, change: func(p *authzsig.AuthorizeParams) { p.RedirectURI += "#fragment" }},
		{name: "disallowed grant", sql: `UPDATE clients SET grant_types='["client_credentials"]'`},
		{name: "disallowed response", sql: `UPDATE clients SET response_types='[]'`},
		{name: "disallowed scope", change: func(p *authzsig.AuthorizeParams) { p.Scope = "openid offline_access" }},
		{name: "scope control character", change: func(p *authzsig.AuthorizeParams) { p.Scope = "openid\nemail" }},
		{name: "missing PKCE", change: func(p *authzsig.AuthorizeParams) { p.CodeChallenge, p.CodeChallengeMethod = "", "" }},
		{name: "unsupported PKCE", change: func(p *authzsig.AuthorizeParams) { p.CodeChallengeMethod = "S512" }},
		{name: "plain forbidden", change: func(p *authzsig.AuthorizeParams) { p.CodeChallengeMethod = "plain" }},
		{name: "method without challenge", sql: "UPDATE clients SET client_type='confidential'", change: func(p *authzsig.AuthorizeParams) { p.CodeChallenge = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testutils.WithTestDB(t)
			testutils.WithConfigOverride(t, func() { config.Values.AuthPKCEEnforceSHA256 = !tc.allowPlain })
			testutils.InsertTestClient(t, "rp", []string{"https://rp.example/callback"})
			_, err := db.GetDB().Exec("UPDATE clients SET scopes='openid email'")
			require.NoError(t, err)
			if tc.sql != "" {
				_, err := db.GetDB().Exec(tc.sql)
				require.NoError(t, err)
			}
			p := authzsig.AuthorizeParams{ClientID: "rp", RedirectURI: "https://rp.example/callback", Scope: "openid email", CodeChallenge: "challenge", CodeChallengeMethod: "S256"}
			if tc.change != nil {
				tc.change(&p)
			}
			c, err := ValidateAuthorization(p)
			if tc.valid {
				require.NoError(t, err)
				require.Equal(t, "rp", c.ClientID)
			} else {
				require.Error(t, err)
				require.Nil(t, c)
			}
		})
	}
}
