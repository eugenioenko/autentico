package config

import (
	"time"
)

const (
	AppPort                    = "8080"
	AppBasePath                = "/api/v1/"
	DbFilePath                 = "./auth.db"
	AuthAccessTokenSecret      = "your-secret-here"
	AuthAccessTokenExpiration  = 15 * time.Minute
	AuthRefreshTokenSecret     = "your-secret-here"
	AuthRefreshTokenExpiration = 30 * 24 * time.Hour
	SwaggerPort                = "8888"
)
