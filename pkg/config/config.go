package config

import (
	"fmt"
	"time"
)

type Config struct {
	// AppDomain is the domain name of the application (e.g., "localhost").
	AppDomain string
	// AppHost is the host address combining domain and port (e.g., "localhost:8080").
	AppHost string
	// AppPort is the port on which the application runs (e.g., "8080").
	AppPort string
	// AppURL is the full URL of the application (e.g., "http://localhost:8080").
	AppURL string
	// AppEnableCORS determines if Cross-Origin Resource Sharing (CORS) is enabled for the application.
	AppEnableCORS bool
	// AppOAuthPath is the base path for OAuth2 endpoints (e.g., "/oauth2").
	AppOAuthPath string
	// AppAuthIssuer is the issuer URL for authentication tokens.
	AppAuthIssuer string
	// DbFilePath is the file path for the SQLite database.
	DbFilePath string
	// AuthAccessTokenSecret is the secret key used to sign access tokens.
	AuthAccessTokenSecret string
	// AuthAccessTokenExpiration is the duration for which access tokens are valid.
	AuthAccessTokenExpiration time.Duration
	// AuthRefreshTokenSecret is the secret key used to sign refresh tokens.
	AuthRefreshTokenSecret string
	// AuthRefreshTokenExpiration is the duration for which refresh tokens are valid.
	AuthRefreshTokenExpiration time.Duration
	// AuthRefreshTokenCookieName is the name of the cookie storing the refresh token.
	AuthRefreshTokenCookieName string
	// AuthRefreshTokenAsSecureCookie determines if the refresh token cookie is secure.
	AuthRefreshTokenAsSecureCookie bool
	// AuthDefaultClientID is the default client ID for the application.
	AuthDefaultClientID string
	// AuthDefaultIssuer is the default issuer for authentication.
	AuthDefaultIssuer string
	// AuthAuthorizationCodeExpiration is the duration for which authorization codes are valid.
	AuthAuthorizationCodeExpiration time.Duration
	// AuthCSRFProtectionSecretKey is the secret key used for CSRF protection.
	AuthCSRFProtectionSecretKey string
	// AuthCSRFSecureCookie determines if the CSRF cookie is secure.
	AuthCSRFSecureCookie bool
	// AuthAllowedRedirectURIs is a list of allowed redirect URIs for OAuth2 flows.
	AuthAllowedRedirectURIs []string
	// AuthJwkCertKeyID is the key ID for the JSON Web Key (JWK) used in OIDC.
	AuthJwkCertKeyID string
	// AuthJwkCertFile is the file path to the certificate file for JWK.
	AuthJwkCertFile string
	// SwaggerPort is the port on which the Swagger documentation server runs.
	SwaggerPort string
	// ValidationMinUsernameLength is the minimum length for usernames.
	ValidationMinUsernameLength int
	// ValidationMaxUsernameLength is the maximum length for usernames.
	ValidationMaxUsernameLength int
	// ValidationMinPasswordLength is the minimum length for passwords.
	ValidationMinPasswordLength int
	// ValidationMaxPasswordLength is the maximum length for passwords.
	ValidationMaxPasswordLength int
	// ValidationUsernameIsEmail determines if usernames must be valid email addresses.
	ValidationUsernameIsEmail bool
	// ValidationEmailRequired determines if email is required for user registration.
	ValidationEmailRequired bool
	// AuthAccessTokenAudience is the audience claim for access tokens.
	AuthAccessTokenAudience []string
	// AuthRealmAccessRoles is the list of roles for realm_access claim in access tokens.
	AuthRealmAccessRoles []string
}

const (
	appProtocol         = "http://"
	appDomain           = "localhost"
	appPort             = "9999"
	appOAuthPath        = "/oauth2"
	authDefaultClientID = "el_autentico_!"
)

var defaultConfig = Config{
	AppDomain:                       appDomain,
	AppHost:                         fmt.Sprintf("%s:%s", appDomain, appPort),
	AppPort:                         appPort,
	AppURL:                          fmt.Sprintf("%s%s:%s", appProtocol, appDomain, appPort),
	AppEnableCORS:                   true,
	AppOAuthPath:                    appOAuthPath,
	AppAuthIssuer:                   fmt.Sprintf("%s%s:%s%s", appProtocol, appDomain, appPort, appOAuthPath),
	DbFilePath:                      "./db/auth.db",
	AuthAccessTokenSecret:           "your-secret-here",
	AuthAccessTokenExpiration:       15 * time.Minute,
	AuthRefreshTokenSecret:          "your-secret-here",
	AuthRefreshTokenExpiration:      30 * 24 * time.Hour,
	AuthRefreshTokenCookieName:      "autentico_refresh_token",
	AuthRefreshTokenAsSecureCookie:  false,
	AuthDefaultClientID:             authDefaultClientID,
	AuthAuthorizationCodeExpiration: 10 * time.Minute,
	AuthCSRFProtectionSecretKey:     "your-secret-here",
	AuthCSRFSecureCookie:            false,
	AuthAllowedRedirectURIs:         []string{}, // When sets, restricts redirect uris to the list
	AuthJwkCertKeyID:                "autentico-key-1",
	AuthJwkCertFile:                 "./db/jwk_key.pem",
	SwaggerPort:                     "8888",
	ValidationMinUsernameLength:     4,
	ValidationMaxUsernameLength:     64,
	ValidationMinPasswordLength:     6,
	ValidationMaxPasswordLength:     64,
	ValidationUsernameIsEmail:       true,
	ValidationEmailRequired:         false,
	AuthAccessTokenAudience: []string{
		authDefaultClientID,
		"http://localhost:8080",
	},
	AuthRealmAccessRoles: []string{
		"user",
	},
}

var Values = defaultConfig

func Get() *Config {
	return &Values
}

func GetOriginal() Config {
	return defaultConfig
}
