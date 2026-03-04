package view

import (
	"bytes"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/stretchr/testify/assert"
)

func TestParseTemplate_Execution(t *testing.T) {
	// Setup config for helper test
	config.Bootstrap.AppOAuthPath = "/oauth2"
	
	tmpl, err := ParseTemplate("login")
	assert.NoError(t, err)
	
	var buf bytes.Buffer
	data := map[string]any{
		"Title": "Login",
		"Theme": config.ThemeConfig{Title: "Auth"},
	}
	err = tmpl.ExecuteTemplate(&buf, "layout", data)
	assert.NoError(t, err)
	assert.NotEmpty(t, buf.String())
}
