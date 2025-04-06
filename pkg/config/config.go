package config

import (
	"time"
)

const (
	AppPort                        = "8080"
	AppBasePath                    = "/api/v1"
	DbFilePath                     = "./db/auth.db"
	AuthAccessTokenSecret          = "your-secret-here"
	AuthAccessTokenExpiration      = 15 * time.Minute
	AuthRefreshTokenSecret         = "your-secret-here"
	AuthRefreshTokenExpiration     = 30 * 24 * time.Hour
	AuthRefreshTokenCookieName     = "autentico_refresh_token"
	AuthRefreshTokenAsSecureCookie = true
	AuthDefaultClientID            = "el_autentico_!"
	AuthDefaultIssuer              = "https://autentico.com"
	SwaggerPort                    = "8888"
	ValidationMinUsernameLength    = 4
	ValidationMaxUsernameLength    = 64
	ValidationMinPasswordLength    = 6
	ValidationMaxPasswordLength    = 64
	ValidationUsernameIsEmail      = true
	ValidationEmailRequired        = false
)
