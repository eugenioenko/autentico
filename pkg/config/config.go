package config

import (
	"time"
)

type Config struct {
	AppPort                        string
	AppBasePath                    string
	DbFilePath                     string
	AuthAccessTokenSecret          string
	AuthAccessTokenExpiration      time.Duration
	AuthRefreshTokenSecret         string
	AuthRefreshTokenExpiration     time.Duration
	AuthRefreshTokenCookieName     string
	AuthRefreshTokenAsSecureCookie bool
	AuthDefaultClientID            string
	AuthDefaultIssuer              string
	SwaggerPort                    string
	ValidationMinUsernameLength    int
	ValidationMaxUsernameLength    int
	ValidationMinPasswordLength    int
	ValidationMaxPasswordLength    int
	ValidationUsernameIsEmail      bool
	ValidationEmailRequired        bool
}

var defaultConfig = Config{
	AppPort:                        "8080",
	AppBasePath:                    "/api/v1",
	DbFilePath:                     "./db/auth.db",
	AuthAccessTokenSecret:          "your-secret-here",
	AuthAccessTokenExpiration:      15 * time.Minute,
	AuthRefreshTokenSecret:         "your-secret-here",
	AuthRefreshTokenExpiration:     30 * 24 * time.Hour,
	AuthRefreshTokenCookieName:     "autentico_refresh_token",
	AuthRefreshTokenAsSecureCookie: true,
	AuthDefaultClientID:            "el_autentico_!",
	AuthDefaultIssuer:              "https://autentico.com",
	SwaggerPort:                    "8888",
	ValidationMinUsernameLength:    4,
	ValidationMaxUsernameLength:    64,
	ValidationMinPasswordLength:    6,
	ValidationMaxPasswordLength:    64,
	ValidationUsernameIsEmail:      true,
	ValidationEmailRequired:        false,
}

var Values = defaultConfig

func Get() *Config {
	return &Values
}

func GetOriginal() Config {
	return defaultConfig
}
