package email

import (
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSendEmailOTP_NoHost(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		config.Values.SmtpHost = ""
		err := SendEmailOTP("test@test.com", "123456")
		assert.Error(t, err)
		assert.Equal(t, "SMTP is not configured", err.Error())
	})
}

func TestBuildEmailHTML_SanitizesFooterLinks(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		config.Values.FooterLinks = []config.FooterLink{
			{Label: "Terms", URL: "https://example.com/terms"},
			{Label: "Evil", URL: "javascript:alert(1)"},
			{Label: "Privacy", URL: "http://example.com/privacy"},
			{Label: "Data", URL: "data:text/html,<script>alert(1)</script>"},
		}

		html, err := buildEmailHTML("Test", "preheader", "body")
		require.NoError(t, err)

		assert.Contains(t, html, "Terms")
		assert.Contains(t, html, "https://example.com/terms")
		assert.Contains(t, html, "Privacy")
		assert.Contains(t, html, "http://example.com/privacy")
		assert.NotContains(t, html, "javascript:")
		assert.NotContains(t, html, "data:")
		assert.NotContains(t, html, "Evil")
		assert.NotContains(t, html, "Data")
	})
}

func TestRenderBody_TestEmail(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		config.Values.Theme.BrandColor = "#ff0000"
		config.Bootstrap.AppURL = "http://localhost:9999"

		body, err := renderBody(bodyTestTmpl, struct {
			BrandColor string
			AdminURL   string
		}{"#ff0000", "http://localhost:9999/admin"})
		require.NoError(t, err)

		html := string(body)
		assert.Contains(t, html, "#ff0000")
		assert.Contains(t, html, "http://localhost:9999/admin")
		assert.Contains(t, html, "Go to admin")
	})
}

func TestRenderBody_VerificationEmail(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		body, err := renderBody(bodyVerifyTmpl, struct {
			BrandColor string
			VerifyURL  string
		}{"#18181b", "http://localhost:9999/verify?token=abc123"})
		require.NoError(t, err)

		html := string(body)
		assert.Contains(t, html, "http://localhost:9999/verify?token=abc123")
		assert.Contains(t, html, "Verify my email")
		assert.Contains(t, html, "24 hours")
	})
}

func TestRenderBody_PasswordResetEmail(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		body, err := renderBody(bodyResetTmpl, struct {
			BrandColor string
			ResetURL   string
		}{"#18181b", "http://localhost:9999/reset?token=xyz789"})
		require.NoError(t, err)

		html := string(body)
		assert.Contains(t, html, "http://localhost:9999/reset?token=xyz789")
		assert.Contains(t, html, "Reset my password")
		assert.Contains(t, html, "1 hour")
	})
}

func TestRenderBody_OTPEmail(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		body, err := renderBody(bodyOTPTmpl, struct {
			Code string
		}{"847291"})
		require.NoError(t, err)

		html := string(body)
		assert.Contains(t, html, "847291")
		assert.Contains(t, html, "5 minutes")
		assert.Contains(t, html, "Do not share")
	})
}

func TestBuildEmailHTML_RendersAllFields(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		config.Values.Theme.Title = "MyApp"
		config.Values.Theme.LogoUrl = "https://example.com/logo.png"
		config.Values.Theme.BrandColor = "#ff7b00"
		config.Values.Theme.Tagline = "Secure by default"
		config.Values.Theme.EmailFooterText = "Copyright 2026 Acme\n123 Main St"
		config.Values.FooterLinks = []config.FooterLink{
			{Label: "Terms", URL: "https://example.com/terms"},
		}
		config.Bootstrap.AppURL = "http://localhost:9999"

		html, err := buildEmailHTML("Welcome", "preheader text", "<p>Hello</p>")
		require.NoError(t, err)

		assert.Contains(t, html, "MyApp")
		assert.Contains(t, html, "https://example.com/logo.png")
		assert.Contains(t, html, "Secure by default")
		assert.Contains(t, html, "Welcome")
		assert.Contains(t, html, "preheader text")
		assert.Contains(t, html, "<p>Hello</p>")
		assert.Contains(t, html, "http://localhost:9999/account")
		assert.Contains(t, html, "Terms")
		assert.Contains(t, html, "https://example.com/terms")
		assert.Contains(t, html, "Copyright 2026 Acme")
		assert.Contains(t, html, "123 Main St")
	})
}

func TestBuildEmailHTML_DefaultsWhenEmpty(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		config.Values.Theme.Title = ""
		config.Values.Theme.LogoUrl = ""
		config.Values.Theme.BrandColor = ""
		config.Values.Theme.Tagline = ""
		config.Values.Theme.EmailFooterText = ""
		config.Values.FooterLinks = nil
		config.Bootstrap.AppURL = "http://localhost:9999"

		html, err := buildEmailHTML("Test", "pre", "body")
		require.NoError(t, err)

		assert.Contains(t, html, "Autentico")
		assert.Contains(t, html, "http://localhost:9999/oauth2/static/logo.svg")
		assert.NotContains(t, html, "Tagline")
		assert.Contains(t, html, "Manage your account")
	})
}
