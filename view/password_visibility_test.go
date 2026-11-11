package view

import (
	"bytes"
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/stretchr/testify/require"
)

func TestPasswordPagesProgressiveEnhancement(t *testing.T) {
	previous := config.Bootstrap.AppOAuthPath
	config.Bootstrap.AppOAuthPath = "/oauth2"
	t.Cleanup(func() { config.Bootstrap.AppOAuthPath = previous })
	for _, tc := range []struct {
		page         string
		fields       int
		autocomplete string
	}{
		{"login", 1, "current-password"},
		{"signup", 2, "new-password"},
		{"reset_password", 2, "new-password"},
		{"onboard", 2, "new-password"},
	} {
		t.Run(tc.page, func(t *testing.T) {
			tmpl, err := ParseTemplate(tc.page)
			require.NoError(t, err)
			var out bytes.Buffer
			require.NoError(t, tmpl.ExecuteTemplate(&out, "layout", map[string]any{"CspNonce": "test-nonce", "AuthMode": "password"}))
			html := out.String()
			require.Equal(t, tc.fields, strings.Count(html, `type="password"`))
			require.Equal(t, tc.fields, strings.Count(html, `autocomplete="`+tc.autocomplete+`"`))
			require.Contains(t, html, `<script nonce="test-nonce" src="/oauth2/static/main.js"></script>`)
			// Without JavaScript no misleading, nonfunctional visibility button is rendered.
			require.NotContains(t, html, `aria-label="Show password"`)
			require.NotContains(t, html, `onclick=`)
		})
	}
	t.Run("passwordless login", func(t *testing.T) {
		tmpl, err := ParseTemplate("login")
		require.NoError(t, err)
		var out bytes.Buffer
		require.NoError(t, tmpl.ExecuteTemplate(&out, "layout", map[string]any{"HidePasswordField": true}))
		require.NotContains(t, out.String(), `type="password"`)
	})
}
