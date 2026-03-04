package appsettings

import (
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
)

func TestEnsureDefaults(t *testing.T) {
	testutils.WithTestDB(t)

	// Defaults should be empty initially in a fresh test DB (Wait, WithTestDB runs migrations but not app-level seeds usually)
	// Actually EnsureDefaults is what we are testing.

	err := EnsureDefaults()
	assert.NoError(t, err)

	val, err := GetSetting("access_token_expiration")
	assert.NoError(t, err)
	assert.Equal(t, "15m", val)

	// Change a value and ensure it's not overwritten
	err = SetSetting("access_token_expiration", "30m")
	assert.NoError(t, err)

	err = EnsureDefaults()
	assert.NoError(t, err)

	val, err = GetSetting("access_token_expiration")
	assert.NoError(t, err)
	assert.Equal(t, "30m", val)
}

func TestLoadIntoConfig(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		// Set some values in DB
		_ = SetSetting("access_token_expiration", "45m")
		_ = SetSetting("refresh_token_expiration", "100h")
		_ = SetSetting("authorization_code_expiration", "5m")
		_ = SetSetting("allow_self_signup", "true")
		_ = SetSetting("validation_min_username_length", "10")
		_ = SetSetting("validation_max_username_length", "100")
		_ = SetSetting("validation_min_password_length", "8")
		_ = SetSetting("validation_max_password_length", "128")
		_ = SetSetting("access_token_audience", `["aud1", "aud2"]`)
		_ = SetSetting("sso_session_idle_timeout", "1h")
		_ = SetSetting("allow_username_change", "true")
		_ = SetSetting("allow_email_change", "true")
		_ = SetSetting("signup_show_optional_fields", "true")
		_ = SetSetting("profile_field_email", "required")
		_ = SetSetting("account_lockout_max_attempts", "10")
		_ = SetSetting("account_lockout_duration", "30m")
		_ = SetSetting("auth_mode", "passkey_only")
		_ = SetSetting("passkey_rp_name", "TestRP")
		_ = SetSetting("trust_device_enabled", "true")
		_ = SetSetting("trust_device_expiration", "1000h")
		_ = SetSetting("cleanup_interval", "12h")
		_ = SetSetting("cleanup_retention", "48h")
		_ = SetSetting("pkce_enforce_s256", "false")
		_ = SetSetting("require_mfa", "true")
		_ = SetSetting("mfa_method", "email")
		_ = SetSetting("smtp_host", "smtp.test.com")
		_ = SetSetting("smtp_port", "25")
		_ = SetSetting("smtp_username", "user")
		_ = SetSetting("smtp_password", "pass")
		_ = SetSetting("smtp_from", "auth@test.com")
		_ = SetSetting("theme_title", "Custom Title")
		_ = SetSetting("theme_logo_url", "http://logo.com")
		_ = SetSetting("theme_css_inline", "body { color: red; }")
		_ = SetSetting("profile_field_given_name", "required")
		_ = SetSetting("profile_field_family_name", "required")
		_ = SetSetting("profile_field_phone", "required")
		_ = SetSetting("profile_field_picture", "required")
		_ = SetSetting("profile_field_locale", "required")
		_ = SetSetting("profile_field_address", "required")

		err := LoadIntoConfig()
		assert.NoError(t, err)

		cfg := config.Get()
		assert.Equal(t, 45*time.Minute, cfg.AuthAccessTokenExpiration)
		assert.Equal(t, 100*time.Hour, cfg.AuthRefreshTokenExpiration)
		assert.Equal(t, 5*time.Minute, cfg.AuthAuthorizationCodeExpiration)
		assert.True(t, cfg.AuthAllowSelfSignup)
		assert.Equal(t, 10, cfg.ValidationMinUsernameLength)
		assert.Equal(t, 100, cfg.ValidationMaxUsernameLength)
		assert.Equal(t, 8, cfg.ValidationMinPasswordLength)
		assert.Equal(t, 128, cfg.ValidationMaxPasswordLength)
		assert.Equal(t, []string{"aud1", "aud2"}, cfg.AuthAccessTokenAudience)
		assert.Equal(t, time.Hour, cfg.AuthSsoSessionIdleTimeout)
		assert.True(t, cfg.AllowUsernameChange)
		assert.True(t, cfg.AllowEmailChange)
		assert.True(t, cfg.SignupShowOptionalFields)
		assert.Equal(t, "required", cfg.ProfileFieldEmail)
		assert.Equal(t, 10, cfg.AuthAccountLockoutMaxAttempts)
		assert.Equal(t, 30*time.Minute, cfg.AuthAccountLockoutDuration)
		assert.Equal(t, "passkey_only", cfg.AuthMode)
		assert.Equal(t, "TestRP", cfg.PasskeyRPName)
		assert.True(t, cfg.TrustDeviceEnabled)
		assert.Equal(t, 1000*time.Hour, cfg.TrustDeviceExpiration)
		assert.Equal(t, 12*time.Hour, cfg.CleanupInterval)
		assert.Equal(t, 48*time.Hour, cfg.CleanupRetention)
		assert.False(t, cfg.AuthPKCEEnforceSHA256)
		assert.True(t, cfg.RequireMfa)
		assert.Equal(t, "email", cfg.MfaMethod)
		assert.Equal(t, "smtp.test.com", cfg.SmtpHost)
		assert.Equal(t, "25", cfg.SmtpPort)
		assert.Equal(t, "user", cfg.SmtpUsername)
		assert.Equal(t, "pass", cfg.SmtpPassword)
		assert.Equal(t, "auth@test.com", cfg.SmtpFrom)
		assert.Equal(t, "Custom Title", cfg.Theme.Title)
		assert.Equal(t, "http://logo.com", cfg.Theme.LogoUrl)
		assert.Equal(t, "body { color: red; }", cfg.Theme.CssInline)
		assert.Equal(t, "required", cfg.ProfileFieldGivenName)
		assert.Equal(t, "required", cfg.ProfileFieldFamilyName)
		assert.Equal(t, "required", cfg.ProfileFieldPhone)
		assert.Equal(t, "required", cfg.ProfileFieldPicture)
		assert.Equal(t, "required", cfg.ProfileFieldLocale)
		assert.Equal(t, "required", cfg.ProfileFieldAddress)
	})
}

func TestParseBool(t *testing.T) {
	assert.True(t, parseBool("true", false))
	assert.True(t, parseBool("1", false))
	assert.False(t, parseBool("false", true))
	assert.False(t, parseBool("invalid", false))
}

func TestLoadIntoConfig_InvalidAudienceJSON(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		// Set original to something known
		config.Values.AuthAccessTokenAudience = []string{"original"}
		
		// Set invalid JSON for audience
		_ = SetSetting("access_token_audience", "invalid-json")

		err := LoadIntoConfig()
		assert.NoError(t, err)
		
		// It should NOT have updated the audience
		assert.Equal(t, []string{"original"}, config.Values.AuthAccessTokenAudience)
	})
}
