package view

import (
	"bytes"
	"html/template"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/stretchr/testify/assert"
)

func TestParseTemplate(t *testing.T) {
	// Test parsing a few templates
	names := []string{"login", "signup", "error", "onboard"}
	for _, name := range names {
		tmpl, err := ParseTemplate(name)
		assert.NoError(t, err, "failed to parse template: %s", name)
		assert.NotNil(t, tmpl)
	}

	// Test invalid template
	_, err := ParseTemplate("nonexistent")
	assert.Error(t, err)
}

func TestTemplateHelpersExecution(t *testing.T) {
	// Setup config for helper test
	config.Bootstrap.AppOAuthPath = "/custom-oauth"
	
	// Define the same funcs as in ParseTemplate to test them
	funcs := template.FuncMap{
		"authURL": func(path string) string {
			return config.GetBootstrap().AppOAuthPath + path
		},
		"safeHTML": func(s string) template.HTML {
			return template.HTML(s)
		},
	}

	t.Run("authURL", func(t *testing.T) {
		tHelper, err := template.New("test").Funcs(funcs).Parse(`{{authURL "/foo"}}`)
		assert.NoError(t, err)
		
		var buf bytes.Buffer
		err = tHelper.Execute(&buf, nil)
		assert.NoError(t, err)
		assert.Equal(t, "/custom-oauth/foo", buf.String())
	})

	t.Run("safeHTML", func(t *testing.T) {
		tHelper, err := template.New("test").Funcs(funcs).Parse(`{{safeHTML "<b>bar</b>"}}`)
		assert.NoError(t, err)
		
		var buf bytes.Buffer
		err = tHelper.Execute(&buf, nil)
		assert.NoError(t, err)
		assert.Equal(t, "<b>bar</b>", buf.String())
	})
}
