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
	config.Bootstrap.AppOAuthPath = "/custom-oauth"

	funcs := template.FuncMap{
		"authURL": func(path string) string {
			return config.GetBootstrap().AppOAuthPath + path
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
}
