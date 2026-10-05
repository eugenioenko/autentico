package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func withAppURL(t *testing.T, appURL string) {
	original := Bootstrap.AppURL
	Bootstrap.AppURL = appURL
	t.Cleanup(func() { Bootstrap.AppURL = original })
}

func TestValidateLogoURL_Accepted(t *testing.T) {
	withAppURL(t, "http://localhost:9999")
	for _, v := range []string{
		"",
		"https://cdn.example.com/logo.svg",
		"/oauth2/static/logo.svg",
		"http://localhost:9999/custom/logo.png",
		"data:image/png;base64,iVBORw0KGgo=",
		"data:image/svg+xml,%3Csvg%3E%3C/svg%3E",
	} {
		assert.NoError(t, ValidateLogoURL(v), v)
	}
}

func TestValidateLogoURL_Rejected(t *testing.T) {
	withAppURL(t, "http://localhost:9999")
	for _, v := range []string{
		"javascript:alert(1)",
		"http://cdn.example.com/logo.svg",
		"//cdn.example.com/logo.svg",
		"/\\cdn.example.com/logo.svg",
		"data:text/html,<script>alert(1)</script>",
		"data:image/svg",
		"https://user:pass@cdn.example.com/logo.svg",
		"logo.svg",
		"ftp://cdn.example.com/logo.svg",
	} {
		assert.Error(t, ValidateLogoURL(v), v)
	}
}

func TestLogoOrigin(t *testing.T) {
	withAppURL(t, "https://auth.example.com")
	cases := map[string]string{
		"":                                     "",
		"https://cdn.example.com/a/logo.svg?v=1": "https://cdn.example.com",
		"https://cdn.example.com:8443/logo.svg": "https://cdn.example.com:8443",
		"https://auth.example.com/logo.svg":     "",
		"/oauth2/static/logo.svg":               "",
		"data:image/png;base64,iVBORw0KGgo=":    "",
		"http://cdn.example.com/logo.svg":       "",
		"javascript:alert(1)":                   "",
	}
	for in, want := range cases {
		assert.Equal(t, want, LogoOrigin(in), in)
	}
}
