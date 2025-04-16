package config

import (
	"fmt"
	"time"
)

type Config struct {
	AppHost                         string
	AppPort                         string
	AppURL                          string
	AppOAuthPath                    string
	AppAuthIssuer                   string
	DbFilePath                      string
	AuthAccessTokenSecret           string
	AuthAccessTokenExpiration       time.Duration
	AuthRefreshTokenSecret          string
	AuthRefreshTokenExpiration      time.Duration
	AuthRefreshTokenCookieName      string
	AuthRefreshTokenAsSecureCookie  bool
	AuthDefaultClientID             string
	AuthDefaultIssuer               string
	AuthAuthorizationCodeExpiration time.Duration
	SwaggerPort                     string
	ValidationMinUsernameLength     int
	ValidationMaxUsernameLength     int
	ValidationMinPasswordLength     int
	ValidationMaxPasswordLength     int
	ValidationUsernameIsEmail       bool
	ValidationEmailRequired         bool
}

const (
	appHost      = "http://localhost"
	appPort      = "8080"
	appOAuthPath = "/oauth2"
)

var defaultConfig = Config{
	AppHost:                         appHost,
	AppPort:                         appPort,
	AppURL:                          fmt.Sprintf("%s:%s", appHost, appPort),
	AppOAuthPath:                    appOAuthPath,
	AppAuthIssuer:                   fmt.Sprintf("%s:%s%s", appHost, appPort, appOAuthPath),
	DbFilePath:                      "./db/auth.db",
	AuthAccessTokenSecret:           "your-secret-here",
	AuthAccessTokenExpiration:       15 * time.Minute,
	AuthRefreshTokenSecret:          "your-secret-here",
	AuthRefreshTokenExpiration:      30 * 24 * time.Hour,
	AuthRefreshTokenCookieName:      "autentico_refresh_token",
	AuthRefreshTokenAsSecureCookie:  true,
	AuthDefaultClientID:             "el_autentico_!",
	AuthAuthorizationCodeExpiration: 10 * time.Minute,
	SwaggerPort:                     "8888",
	ValidationMinUsernameLength:     4,
	ValidationMaxUsernameLength:     64,
	ValidationMinPasswordLength:     6,
	ValidationMaxPasswordLength:     64,
	ValidationUsernameIsEmail:       true,
	ValidationEmailRequired:         false,
}

var Values = defaultConfig

func Get() *Config {
	return &Values
}

func GetOriginal() Config {
	return defaultConfig
}
