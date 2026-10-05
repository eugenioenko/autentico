package view

import (
	"bytes"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/stretchr/testify/assert"
)

func TestParseTemplate_LogoURL(t *testing.T) {
	config.Bootstrap.AppOAuthPath = "/oauth2"

	render := func(logo string) string {
		tmpl, err := ParseTemplate("error")
		assert.NoError(t, err)
		var buf bytes.Buffer
		assert.NoError(t, tmpl.ExecuteTemplate(&buf, "layout", map[string]any{"ThemeLogoUrl": logo, "CspNonce": "n"}))
		return buf.String()
	}

	dataURI := "data:image/png;base64,iVBORw0KGgo="
	out := render(dataURI)
	assert.Contains(t, out, `<img src="`+dataURI+`"`)
	assert.Contains(t, out, `<link rel="icon" type="image/svg+xml" href="`+dataURI+`"`)
	assert.NotContains(t, out, "ZgotmplZ")

	assert.Contains(t, render("https://cdn.example.com/logo.svg"), `<img src="https://cdn.example.com/logo.svg"`)
	assert.Contains(t, render(""), `<img src="/oauth2/static/logo.svg"`)

	out = render("javascript:alert(1)")
	assert.Contains(t, out, `<img src="/oauth2/static/logo.svg"`)
	assert.NotContains(t, out, "javascript:")
}

func TestParseTemplate_Execution(t *testing.T) {
	// Setup config for helper test
	config.Bootstrap.AppOAuthPath = "/oauth2"
	
	tmpl, err := ParseTemplate("login")
	assert.NoError(t, err)
	
	var buf bytes.Buffer
	data := map[string]any{
		"Title":    "Login",
		"Theme":    config.ThemeConfig{Title: "Auth"},
		"CspNonce": "test-nonce",
	}
	err = tmpl.ExecuteTemplate(&buf, "layout", data)
	assert.NoError(t, err)
	assert.NotEmpty(t, buf.String())
}
