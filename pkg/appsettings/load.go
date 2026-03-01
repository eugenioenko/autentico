package appsettings

import (
	"encoding/json"
	"os"
	"strconv"

	"github.com/eugenioenko/autentico/pkg/config"
)

// defaults maps each well-known settings key to its default string value.
var defaults = map[string]string{
	"access_token_expiration":        "15m",
	"refresh_token_expiration":       "720h",
	"authorization_code_expiration":  "10m",
	"access_token_audience":          "[]",
	"allow_self_signup":              "false",
	"sso_session_idle_timeout":       "0",
	"validation_min_username_length": "4",
	"validation_max_username_length": "64",
	"validation_min_password_length": "6",
	"validation_max_password_length": "64",
	"validation_username_is_email":   "false",
	"validation_email_required":      "false",
	"account_lockout_max_attempts":   "5",
	"account_lockout_duration":       "15m",
	"auth_mode":                      "password",
	"passkey_rp_name":                "Autentico",
	"trust_device_enabled":           "false",
	"trust_device_expiration":        "720h",
	"cleanup_interval":               "6h",
	"cleanup_retention":              "24h",
	"pkce_enforce_s256":              "true",
	"mfa_enabled":                    "false",
	"mfa_method":                     "totp",
	"smtp_port":                      "587",
	"theme_title":                    "Autentico",
	"onboarded":                      "false",
}

// EnsureDefaults writes any missing well-known keys with their default values.
// Existing values are never overwritten.
func EnsureDefaults() error {
	for k, v := range defaults {
		if existing, err := GetSetting(k); err != nil || existing == "" {
			if err := SetSetting(k, v); err != nil {
				return err
			}
		}
	}
	return nil
}

// LoadIntoConfig reads all settings from the DB and populates config.Values.
func LoadIntoConfig() error {
	all, err := GetAllSettings()
	if err != nil {
		return err
	}

	cfg := config.Values

	if v, ok := all["access_token_expiration"]; ok {
		cfg.AuthAccessTokenExpirationStr = v
		cfg.AuthAccessTokenExpiration = config.ParseDuration(v, cfg.AuthAccessTokenExpiration)
	}
	if v, ok := all["refresh_token_expiration"]; ok {
		cfg.AuthRefreshTokenExpirationStr = v
		cfg.AuthRefreshTokenExpiration = config.ParseDuration(v, cfg.AuthRefreshTokenExpiration)
	}
	if v, ok := all["authorization_code_expiration"]; ok {
		cfg.AuthAuthorizationCodeExpirationStr = v
		cfg.AuthAuthorizationCodeExpiration = config.ParseDuration(v, cfg.AuthAuthorizationCodeExpiration)
	}
	if v, ok := all["access_token_audience"]; ok {
		var aud []string
		if err := json.Unmarshal([]byte(v), &aud); err == nil {
			cfg.AuthAccessTokenAudience = aud
		}
	}
	if v, ok := all["allow_self_signup"]; ok {
		cfg.AuthAllowSelfSignup = parseBool(v, false)
	}
	if v, ok := all["sso_session_idle_timeout"]; ok {
		cfg.AuthSsoSessionIdleTimeoutStr = v
		cfg.AuthSsoSessionIdleTimeout = config.ParseDuration(v, 0)
	}
	if v, ok := all["validation_min_username_length"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.ValidationMinUsernameLength = n
		}
	}
	if v, ok := all["validation_max_username_length"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.ValidationMaxUsernameLength = n
		}
	}
	if v, ok := all["validation_min_password_length"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.ValidationMinPasswordLength = n
		}
	}
	if v, ok := all["validation_max_password_length"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.ValidationMaxPasswordLength = n
		}
	}
	if v, ok := all["validation_username_is_email"]; ok {
		cfg.ValidationUsernameIsEmail = parseBool(v, false)
	}
	if v, ok := all["validation_email_required"]; ok {
		cfg.ValidationEmailRequired = parseBool(v, false)
	}
	if v, ok := all["account_lockout_max_attempts"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.AuthAccountLockoutMaxAttempts = n
		}
	}
	if v, ok := all["account_lockout_duration"]; ok {
		cfg.AuthAccountLockoutDurationStr = v
		cfg.AuthAccountLockoutDuration = config.ParseDuration(v, cfg.AuthAccountLockoutDuration)
	}
	if v, ok := all["auth_mode"]; ok {
		cfg.AuthMode = v
	}
	if v, ok := all["passkey_rp_name"]; ok {
		cfg.PasskeyRPName = v
	}
	if v, ok := all["trust_device_enabled"]; ok {
		cfg.TrustDeviceEnabled = parseBool(v, false)
	}
	if v, ok := all["trust_device_expiration"]; ok {
		cfg.TrustDeviceExpirationStr = v
		cfg.TrustDeviceExpiration = config.ParseDuration(v, cfg.TrustDeviceExpiration)
	}
	if v, ok := all["cleanup_interval"]; ok {
		cfg.CleanupIntervalStr = v
		cfg.CleanupInterval = config.ParseDuration(v, cfg.CleanupInterval)
	}
	if v, ok := all["cleanup_retention"]; ok {
		cfg.CleanupRetentionStr = v
		cfg.CleanupRetention = config.ParseDuration(v, cfg.CleanupRetention)
	}
	if v, ok := all["pkce_enforce_s256"]; ok {
		cfg.AuthPKCEEnforceSHA256 = parseBool(v, true)
	}
	if v, ok := all["mfa_enabled"]; ok {
		cfg.MfaEnabled = parseBool(v, false)
	}
	if v, ok := all["mfa_method"]; ok {
		cfg.MfaMethod = v
	}
	if v, ok := all["smtp_host"]; ok {
		cfg.SmtpHost = v
	}
	if v, ok := all["smtp_port"]; ok {
		cfg.SmtpPort = v
	}
	if v, ok := all["smtp_username"]; ok {
		cfg.SmtpUsername = v
	}
	if v, ok := all["smtp_password"]; ok {
		cfg.SmtpPassword = v
	}
	if v, ok := all["smtp_from"]; ok {
		cfg.SmtpFrom = v
	}
	if v, ok := all["theme_title"]; ok {
		cfg.Theme.Title = v
	}
	if v, ok := all["theme_logo_url"]; ok {
		cfg.Theme.LogoUrl = v
	}
	if v, ok := all["theme_css_inline"]; ok {
		cfg.Theme.CssInline = v
		cfg.ThemeCssResolved = v
	}
	if v, ok := all["theme_css_file"]; ok && v != "" {
		cfg.Theme.CssFile = v
		if cssBytes, err := os.ReadFile(v); err == nil {
			cfg.ThemeCssResolved = string(cssBytes)
		}
	}

	config.Values = cfg
	return nil
}

// IsOnboarded returns true if the onboarded setting is "true".
func IsOnboarded() bool {
	v, err := GetSetting("onboarded")
	if err != nil {
		return false
	}
	return parseBool(v, false)
}

func parseBool(s string, fallback bool) bool {
	b, err := strconv.ParseBool(s)
	if err != nil {
		return fallback
	}
	return b
}
