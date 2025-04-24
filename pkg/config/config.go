package config

import (
	"fmt"
	"time"
)

type Config struct {
	AppDomain                       string
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
	AuthCSRFProtectionSecretKey     string
	AuthCSRFSecureCookie            bool // set to true in prod over https
	AuthAllowedRedirectURIs         []string
	SwaggerPort                     string
	ValidationMinUsernameLength     int
	ValidationMaxUsernameLength     int
	ValidationMinPasswordLength     int
	ValidationMaxPasswordLength     int
	ValidationUsernameIsEmail       bool
	ValidationEmailRequired         bool
}

const (
	appProtocol  = "http://"
	appDomain    = "localhost"
	appPort      = "8080"
	appOAuthPath = "/oauth2"
)

var defaultConfig = Config{
	AppDomain:                       appDomain,
	AppHost:                         fmt.Sprintf("%s:%s", appDomain, appPort),
	AppPort:                         appPort,
	AppURL:                          fmt.Sprintf("%s%s:%s", appProtocol, appDomain, appPort),
	AppOAuthPath:                    appOAuthPath,
	AppAuthIssuer:                   fmt.Sprintf("%s%s:%s%s", appProtocol, appDomain, appPort, appOAuthPath),
	DbFilePath:                      "./db/auth.db",
	AuthAccessTokenSecret:           "your-secret-here",
	AuthAccessTokenExpiration:       15 * time.Minute,
	AuthRefreshTokenSecret:          "your-secret-here",
	AuthRefreshTokenExpiration:      30 * 24 * time.Hour,
	AuthRefreshTokenCookieName:      "autentico_refresh_token",
	AuthRefreshTokenAsSecureCookie:  true,
	AuthDefaultClientID:             "el_autentico_!",
	AuthAuthorizationCodeExpiration: 10 * time.Minute,
	AuthCSRFProtectionSecretKey:     "your-secret-here",
	AuthCSRFSecureCookie:            false,
	AuthAllowedRedirectURIs:         []string{}, // When sets, restricts redirect uris to the list
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
