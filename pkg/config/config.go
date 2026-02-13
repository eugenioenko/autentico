package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type ThemeConfig struct {
	CssFile   string `json:"themeCssFile"`
	CssInline string `json:"themeCssInline"`
	LogoUrl   string `json:"themeLogoUrl"`
	Title     string `json:"themeTitle"`
}

type Config struct {
	AppDomain                          string        `json:"appDomain"`
	AppHost                            string        `json:"appHost"`
	AppPort                            string        `json:"appPort"`
	AppURL                             string        `json:"appUrl"`
	AppEnableCORS                      bool          `json:"appEnableCORS"`
	AppOAuthPath                       string        `json:"appOAuthPath"`
	AppAuthIssuer                      string        `json:"appAuthIssuer"`
	DbFilePath                         string        `json:"dbFilePath"`
	AuthAccessTokenSecret              string        `json:"authAccessTokenSecret"`
	AuthAccessTokenExpiration          time.Duration `json:"-"`
	AuthAccessTokenExpirationStr       string        `json:"authAccessTokenExpiration"`
	AuthRefreshTokenSecret             string        `json:"authRefreshTokenSecret"`
	AuthRefreshTokenExpiration         time.Duration `json:"-"`
	AuthRefreshTokenExpirationStr      string        `json:"authRefreshTokenExpiration"`
	AuthRefreshTokenCookieName         string        `json:"authRefreshTokenCookieName"`
	AuthRefreshTokenAsSecureCookie     bool          `json:"authRefreshTokenAsSecureCookie"`
	AuthDefaultClientID                string        `json:"authDefaultClientID"`
	AuthDefaultIssuer                  string        `json:"authDefaultIssuer"`
	AuthAuthorizationCodeExpiration    time.Duration `json:"-"`
	AuthAuthorizationCodeExpirationStr string        `json:"authAuthorizationCodeExpiration"`
	AuthCSRFProtectionSecretKey        string        `json:"authCSRFProtectionSecretKey"`
	AuthCSRFSecureCookie               bool          `json:"authCSRFSecureCookie"`
	AuthAllowedRedirectURIs            []string      `json:"authAllowedRedirectURIs"`
	AuthJwkCertKeyID                   string        `json:"authJwkCertKeyID"`
	AuthPrivateKeyFile                 string        `json:"authPrivateKeyFile"`
	SwaggerPort                        string        `json:"swaggerPort"`
	ValidationMinUsernameLength        int           `json:"validationMinUsernameLength"`
	ValidationMaxUsernameLength        int           `json:"validationMaxUsernameLength"`
	ValidationMinPasswordLength        int           `json:"validationMinPasswordLength"`
	ValidationMaxPasswordLength        int           `json:"validationMaxPasswordLength"`
	ValidationUsernameIsEmail          bool          `json:"validationUsernameIsEmail"`
	ValidationEmailRequired            bool          `json:"validationEmailRequired"`
	AuthAccessTokenAudience            []string      `json:"authAccessTokenAudience"`
	AuthRealmAccessRoles               []string      `json:"authRealmAccessRoles"`
	AuthSsoSessionIdleTimeout          time.Duration `json:"-"`
	AuthSsoSessionIdleTimeoutStr       string        `json:"authSsoSessionIdleTimeout"`
	AuthIdpSessionCookieName           string        `json:"authIdpSessionCookieName"`
	AuthIdpSessionSecureCookie         bool          `json:"authIdpSessionSecureCookie"`
	AuthAccountLockoutMaxAttempts      int           `json:"authAccountLockoutMaxAttempts"`
	AuthAccountLockoutDuration         time.Duration `json:"-"`
	AuthAccountLockoutDurationStr      string        `json:"authAccountLockoutDuration"`
	Theme                              ThemeConfig   `json:"theme"`
	ThemeCssResolved                   string        `json:"-"`
}

var defaultConfig = Config{
	AppDomain:                          "localhost",
	AppHost:                            "localhost:9999",
	AppPort:                            "9999",
	AppURL:                             "http://localhost:9999",
	AppEnableCORS:                      true,
	AppOAuthPath:                       "/oauth2",
	AppAuthIssuer:                      "http://localhost:9999/oauth2",
	DbFilePath:                         "./db/autentico.db",
	AuthAccessTokenSecret:              "your-secret-here",
	AuthAccessTokenExpiration:          15 * time.Minute,
	AuthAccessTokenExpirationStr:       "15m",
	AuthRefreshTokenSecret:             "your-secret-here",
	AuthRefreshTokenExpiration:         30 * 24 * time.Hour,
	AuthRefreshTokenExpirationStr:      "720h",
	AuthRefreshTokenCookieName:         "autentico_refresh_token",
	AuthRefreshTokenAsSecureCookie:     false,
	AuthDefaultClientID:                "el_autentico_!",
	AuthDefaultIssuer:                  "",
	AuthAuthorizationCodeExpiration:    10 * time.Minute,
	AuthAuthorizationCodeExpirationStr: "10m",
	AuthCSRFProtectionSecretKey:        "your-secret-here",
	AuthCSRFSecureCookie:               false,
	AuthAllowedRedirectURIs:            []string{},
	AuthJwkCertKeyID:                   "autentico-key-1",
	AuthPrivateKeyFile:                 "./db/private_key.pem",
	SwaggerPort:                        "8888",
	ValidationMinUsernameLength:        4,
	ValidationMaxUsernameLength:        64,
	ValidationMinPasswordLength:        6,
	ValidationMaxPasswordLength:        64,
	ValidationUsernameIsEmail:          true,
	ValidationEmailRequired:            false,
	AuthAccessTokenAudience: []string{
		"el_autentico_!",
	},
	AuthRealmAccessRoles:         []string{},
	AuthSsoSessionIdleTimeout:    0,
	AuthSsoSessionIdleTimeoutStr: "0",
	AuthIdpSessionCookieName:        "autentico_idp_session",
	AuthIdpSessionSecureCookie:      false,
	AuthAccountLockoutMaxAttempts:   5,
	AuthAccountLockoutDuration:      15 * time.Minute,
	AuthAccountLockoutDurationStr:   "15m",
	Theme: ThemeConfig{
		Title: "Autentico",
	},
}

var Values = defaultConfig

func Get() *Config {
	return &Values
}

// InitConfig loads config from autentico.json and sets Values
func InitConfig(path string) error {
	cfg := defaultConfig
	f, err := os.Open(path)
	if err == nil {
		defer func() { _ = f.Close() }()
		dec := json.NewDecoder(f)
		// decode into a map to allow partial override
		var overrides map[string]interface{}
		if err := dec.Decode(&overrides); err == nil {
			// re-marshal and unmarshal into cfg to override only provided fields
			b, _ := json.Marshal(overrides)
			_ = json.Unmarshal(b, &cfg)
		}
	}
	// Parse durations from string fields
	parseDuration := func(s string, fallback time.Duration) time.Duration {
		d, err := time.ParseDuration(s)
		if err != nil {
			return fallback
		}
		return d
	}
	cfg.AuthAccessTokenExpiration = parseDuration(cfg.AuthAccessTokenExpirationStr, defaultConfig.AuthAccessTokenExpiration)
	cfg.AuthRefreshTokenExpiration = parseDuration(cfg.AuthRefreshTokenExpirationStr, defaultConfig.AuthRefreshTokenExpiration)
	cfg.AuthAuthorizationCodeExpiration = parseDuration(cfg.AuthAuthorizationCodeExpirationStr, defaultConfig.AuthAuthorizationCodeExpiration)
	cfg.AuthSsoSessionIdleTimeout = parseDuration(cfg.AuthSsoSessionIdleTimeoutStr, defaultConfig.AuthSsoSessionIdleTimeout)
	cfg.AuthAccountLockoutDuration = parseDuration(cfg.AuthAccountLockoutDurationStr, defaultConfig.AuthAccountLockoutDuration)

	// Resolve theme CSS: file first, inline overrides
	if cfg.Theme.CssFile != "" {
		cssBytes, err := os.ReadFile(cfg.Theme.CssFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not read theme CSS file %q: %v\n", cfg.Theme.CssFile, err)
		} else {
			cfg.ThemeCssResolved = string(cssBytes)
		}
	}
	if cfg.Theme.CssInline != "" {
		cfg.ThemeCssResolved = cfg.Theme.CssInline
	}

	Values = cfg
	return nil
}

// GetOriginal returns the default config for test override purposes
func GetOriginal() Config {
	return defaultConfig
}
