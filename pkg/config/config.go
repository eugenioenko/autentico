package config

import (
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

// BootstrapConfig holds immutable infrastructure settings loaded from environment
// variables at startup. AppDomain, AppHost, AppPort, and AppAuthIssuer are derived
// from AppURL and AppOAuthPath — they are not read from env vars directly.
type BootstrapConfig struct {
	DbFilePath    string
	AppURL        string // AUTENTICO_APP_URL
	AppOAuthPath  string // AUTENTICO_APP_OAUTH_PATH
	// Derived from AppURL — not set by env vars
	AppDomain     string
	AppHost       string
	AppPort       string
	AppAuthIssuer string
	// AUTENTICO_LISTEN_PORT overrides the port the server binds to,
	// while AppURL (and AppAuthIssuer) remain unchanged. Useful when
	// a reverse proxy handles TLS and the public URL differs from the
	// local listen port.
	AppListenPort string
	// Secrets and cookies
	AuthAccessTokenSecret          string
	AuthRefreshTokenSecret         string
	AuthCSRFProtectionSecretKey    string
	AuthCSRFSecureCookie           bool
	AuthJwkCertKeyID               string
	AuthRefreshTokenCookieName string
	AuthRefreshTokenCookieOnly bool
	AuthIdpSessionCookieName       string
	AuthIdpSessionSecureCookie     bool
	// Private key (base64-encoded PEM). If empty, an ephemeral key is used.
	PrivateKeyBase64 string
	// Rate limiting (per-IP, applied to auth endpoints). RPS <= 0 disables.
	RateLimitRPS       float64
	RateLimitBurst     int
	RateLimitRPM       float64
	RateLimitRPMBurst  int
	// Anti-timing delay (ms) added to auth responses to prevent user enumeration.
	// Both set to 0 disables the delay.
	AntiTimingMinMs int
	AntiTimingMaxMs int
}

// ThemeConfig holds theme-related display settings.
type ThemeConfig struct {
	CssFile   string `json:"themeCssFile"`
	CssInline string `json:"themeCssInline"`
	LogoUrl   string `json:"themeLogoUrl"`
	Title     string `json:"themeTitle"`
}

// Config holds soft settings loaded from the settings DB table. These can be
// updated at runtime via the admin-ui without restarting the server.
type Config struct {
	AuthAccessTokenExpiration          time.Duration
	AuthAccessTokenExpirationStr       string
	AuthRefreshTokenExpiration         time.Duration
	AuthRefreshTokenExpirationStr      string
	AuthAuthorizationCodeExpiration    time.Duration
	AuthAuthorizationCodeExpirationStr string
	AuthAccessTokenAudience            []string
	AuthAllowSelfSignup                bool
	AuthSsoSessionIdleTimeout          time.Duration
	AuthSsoSessionIdleTimeoutStr       string
	AuthAccountLockoutMaxAttempts      int
	AuthAccountLockoutDuration         time.Duration
	AuthAccountLockoutDurationStr      string
	AuthMode                           string
	PasskeyRPName                      string
	TrustDeviceEnabled                 bool
	TrustDeviceExpiration              time.Duration
	TrustDeviceExpirationStr           string
	CleanupInterval                    time.Duration
	CleanupIntervalStr                 string
	CleanupRetention                   time.Duration
	CleanupRetentionStr                string
	AuthPKCEEnforceSHA256              bool
	RequireMfa                         bool
	MfaMethod                          string
	RequireEmailVerification           bool
	EmailVerificationExpiration        time.Duration
	EmailVerificationExpirationStr     string
	PasswordResetExpiration            time.Duration
	PasswordResetExpirationStr         string
	AuditLogRetention                  time.Duration
	AuditLogRetentionStr               string
	SmtpHost                           string
	SmtpPort                           string
	SmtpUsername                       string
	SmtpPassword                       string
	SmtpFrom                           string
	ValidationMinUsernameLength        int
	ValidationMaxUsernameLength        int
	ValidationMinPasswordLength        int
	ValidationMaxPasswordLength        int
	Theme                              ThemeConfig
	ThemeCssResolved                   string
	// When true, users can delete their own account immediately without admin approval.
	AllowSelfServiceDeletion bool
	// When false (default), users cannot change their own username via the account portal.
	AllowUsernameChange bool
	// When false (default), users cannot change their own email via the account portal.
	AllowEmailChange bool
	// CORS: parsed from the "cors_allowed_origins" runtime setting.
	CORSAllowedOrigins []string
	CORSAllowAll       bool
	// When false (default), optional profile fields are hidden on the signup form
	// to keep it minimal. Required fields are always shown regardless.
	SignupShowOptionalFields bool
	// Profile field visibility: "hidden" | "optional" | "required"
	// ProfileFieldEmail also accepts "is_username" (username field doubles as email)
	ProfileFieldEmail      string
	ProfileFieldGivenName  string
	ProfileFieldFamilyName string
	ProfileFieldMiddleName string
	ProfileFieldNickname   string
	ProfileFieldPhone      string
	ProfileFieldPicture    string
	ProfileFieldWebsite    string
	ProfileFieldGender     string
	ProfileFieldBirthdate  string
	ProfileFieldProfileURL string
	ProfileFieldLocale     string
	ProfileFieldAddress    string
}

var defaultConfig = Config{
	AuthAccessTokenExpiration:          15 * time.Minute,
	AuthAccessTokenExpirationStr:       "15m",
	AuthRefreshTokenExpiration:         30 * 24 * time.Hour,
	AuthRefreshTokenExpirationStr:      "720h",
	AuthAuthorizationCodeExpiration:    10 * time.Minute,
	AuthAuthorizationCodeExpirationStr: "10m",
	AuthAccessTokenAudience:            []string{},
	AuthAllowSelfSignup:                false,
	AuthSsoSessionIdleTimeout:          4 * time.Hour,
	AuthSsoSessionIdleTimeoutStr:       "4h",
	AuthAccountLockoutMaxAttempts:      5,
	AuthAccountLockoutDuration:         15 * time.Minute,
	AuthAccountLockoutDurationStr:      "15m",
	AuthMode:                           "password",
	PasskeyRPName:                      "Autentico",
	TrustDeviceEnabled:                 false,
	TrustDeviceExpiration:              30 * 24 * time.Hour,
	TrustDeviceExpirationStr:           "720h",
	CleanupInterval:                    6 * time.Hour,
	CleanupIntervalStr:                 "6h",
	CleanupRetention:                   24 * time.Hour,
	CleanupRetentionStr:                "24h",
	AuthPKCEEnforceSHA256:              true,
	RequireMfa:                         false,
	MfaMethod:                          "totp",
	RequireEmailVerification:           false,
	EmailVerificationExpiration:        24 * time.Hour,
	EmailVerificationExpirationStr:     "24h",
	PasswordResetExpiration:            1 * time.Hour,
	PasswordResetExpirationStr:         "1h",
	SmtpPort:                           "587",
	ValidationMinUsernameLength:        4,
	ValidationMaxUsernameLength:        64,
	ValidationMinPasswordLength:        6,
	ValidationMaxPasswordLength:        64,
	Theme:                              ThemeConfig{Title: "Autentico"},
	AllowSelfServiceDeletion:           false,
	AllowUsernameChange:                false,
	AllowEmailChange:                   false,
	SignupShowOptionalFields:           false,
	ProfileFieldEmail:                  "optional",
	ProfileFieldGivenName:              "optional",
	ProfileFieldFamilyName:             "optional",
	ProfileFieldMiddleName:             "hidden",
	ProfileFieldNickname:               "hidden",
	ProfileFieldPhone:                  "optional",
	ProfileFieldPicture:                "optional",
	ProfileFieldWebsite:                "hidden",
	ProfileFieldGender:                 "hidden",
	ProfileFieldBirthdate:              "hidden",
	ProfileFieldProfileURL:             "hidden",
	ProfileFieldLocale:                 "optional",
	ProfileFieldAddress:                "optional",
}

var (
	Bootstrap = BootstrapConfig{
		DbFilePath:                     "./db/autentico.db",
		AppURL:                         "http://localhost:9999",
		AppOAuthPath:                   "/oauth2",
		AppDomain:                      "localhost",
		AppHost:                        "localhost:9999",
		AppPort:                        "9999",
		AppAuthIssuer:                  "http://localhost:9999/oauth2",
		AuthAccessTokenSecret:          "",
		AuthRefreshTokenSecret:         "",
		AuthCSRFProtectionSecretKey:    "",
		AuthCSRFSecureCookie:           false,
		AuthJwkCertKeyID:               "autentico-key-1",
		AuthRefreshTokenCookieName: "autentico_refresh_token",
		AuthRefreshTokenCookieOnly: false,
		AuthIdpSessionCookieName:       "autentico_idp_session",
		AuthIdpSessionSecureCookie:     false,
		RateLimitRPS:                   5,
		RateLimitBurst:                 10,
		RateLimitRPM:                   20,
		RateLimitRPMBurst:              20,
	}
	Values = defaultConfig
)

func GetBootstrap() *BootstrapConfig { return &Bootstrap }

func Get() *Config { return &Values }

// GetOriginal returns the default soft config for test override purposes.
func GetOriginal() Config { return defaultConfig }

// ParseDuration parses a duration string with a fallback value.
func ParseDuration(s string, fallback time.Duration) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		return fallback
	}
	return d
}

// InitBootstrap loads environment variables (from .env file if present, then
// OS env) and populates Bootstrap. AppDomain, AppHost, AppPort and AppAuthIssuer
// are derived from AppURL — they do not need to be set manually.
func InitBootstrap() {
	_ = godotenv.Load() // silent if no .env file in CWD

	// Fallback: check for .env next to the database file (e.g. ./db/.env),
	// which is where --auto-setup writes it for Docker volume persistence.
	if _, err := os.Stat(".env"); err != nil {
		dbFilePath := os.Getenv("AUTENTICO_DB_FILE_PATH")
		if dbFilePath == "" {
			dbFilePath = "./db/autentico.db"
		}
		dbEnv := filepath.Join(filepath.Dir(dbFilePath), ".env")
		if _, err := os.Stat(dbEnv); err == nil {
			_ = godotenv.Load(dbEnv)
		}
	}

	appURL := getEnv("AUTENTICO_APP_URL", "http://localhost:9999")
	oauthPath := getEnv("AUTENTICO_APP_OAUTH_PATH", "/oauth2")

	// Derive domain/host/port from the URL
	domain := "localhost"
	host := "localhost:9999"
	port := "9999"
	if u, err := url.Parse(appURL); err == nil {
		domain = u.Hostname()
		host = u.Host
		port = u.Port()
		if port == "" {
			// Standard ports (80/443) don't appear in u.Host
			if u.Scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}
	}

	Bootstrap = BootstrapConfig{
		DbFilePath:                     getEnv("AUTENTICO_DB_FILE_PATH", "./db/autentico.db"),
		AppURL:                         appURL,
		AppOAuthPath:                   oauthPath,
		AppDomain:                      domain,
		AppHost:                        host,
		AppPort:                        port,
		AppListenPort:                  getEnv("AUTENTICO_LISTEN_PORT", port),
		AppAuthIssuer:                  appURL + oauthPath,
		AuthAccessTokenSecret:          getEnv("AUTENTICO_ACCESS_TOKEN_SECRET", ""),
		AuthRefreshTokenSecret:         getEnv("AUTENTICO_REFRESH_TOKEN_SECRET", ""),
		AuthCSRFProtectionSecretKey:    getEnv("AUTENTICO_CSRF_SECRET_KEY", ""),
		AuthCSRFSecureCookie:           getEnvBool("AUTENTICO_CSRF_SECURE_COOKIE", true),
		PrivateKeyBase64:               getEnv("AUTENTICO_PRIVATE_KEY", ""),
		AuthJwkCertKeyID:               getEnv("AUTENTICO_JWK_CERT_KEY_ID", "autentico-key-1"),
		AuthRefreshTokenCookieName: getEnv("AUTENTICO_REFRESH_TOKEN_COOKIE_NAME", "autentico_refresh_token"),
		AuthRefreshTokenCookieOnly: getEnvBool("AUTENTICO_REFRESH_TOKEN_COOKIE_ONLY", false),
		AuthIdpSessionCookieName:       getEnv("AUTENTICO_IDP_SESSION_COOKIE_NAME", "autentico_idp_session"),
		AuthIdpSessionSecureCookie:     getEnvBool("AUTENTICO_IDP_SESSION_SECURE", true),
		RateLimitRPS:                   getEnvFloat("AUTENTICO_RATE_LIMIT_RPS", 5),
		RateLimitBurst:                 getEnvInt("AUTENTICO_RATE_LIMIT_BURST", 10),
		RateLimitRPM:                   getEnvFloat("AUTENTICO_RATE_LIMIT_RPM", 20),
		RateLimitRPMBurst:              getEnvInt("AUTENTICO_RATE_LIMIT_RPM_BURST", 20),
		AntiTimingMinMs:                getEnvInt("AUTENTICO_ANTI_TIMING_MIN_MS", 50),
		AntiTimingMaxMs:                getEnvInt("AUTENTICO_ANTI_TIMING_MAX_MS", 150),
	}
}

// GetForClient returns a copy of the current soft Config with any non-nil
// per-client overrides applied. Pass the overrides as a ClientOverrides struct.
func GetForClient(overrides ClientOverrides) Config {
	cfg := Values
	if overrides.AccessTokenExpiration != nil {
		cfg.AuthAccessTokenExpiration = ParseDuration(*overrides.AccessTokenExpiration, cfg.AuthAccessTokenExpiration)
	}
	if overrides.RefreshTokenExpiration != nil {
		cfg.AuthRefreshTokenExpiration = ParseDuration(*overrides.RefreshTokenExpiration, cfg.AuthRefreshTokenExpiration)
	}
	if overrides.AuthorizationCodeExpiration != nil {
		cfg.AuthAuthorizationCodeExpiration = ParseDuration(*overrides.AuthorizationCodeExpiration, cfg.AuthAuthorizationCodeExpiration)
	}
	if overrides.AllowedAudiences != nil {
		cfg.AuthAccessTokenAudience = append(cfg.AuthAccessTokenAudience, overrides.AllowedAudiences...)
	}
	if overrides.AllowSelfSignup != nil {
		cfg.AuthAllowSelfSignup = *overrides.AllowSelfSignup
	}
	if overrides.SsoSessionIdleTimeout != nil {
		cfg.AuthSsoSessionIdleTimeout = ParseDuration(*overrides.SsoSessionIdleTimeout, cfg.AuthSsoSessionIdleTimeout)
	}
	if overrides.TrustDeviceEnabled != nil {
		cfg.TrustDeviceEnabled = *overrides.TrustDeviceEnabled
	}
	if overrides.TrustDeviceExpiration != nil {
		cfg.TrustDeviceExpiration = ParseDuration(*overrides.TrustDeviceExpiration, cfg.TrustDeviceExpiration)
	}
	return cfg
}

// ClientOverrides holds nullable per-client config fields. A nil pointer means
// "use the global setting"; a non-nil pointer overrides it.
type ClientOverrides struct {
	AccessTokenExpiration       *string
	RefreshTokenExpiration      *string
	AuthorizationCodeExpiration *string
	AllowedAudiences            []string
	AllowSelfSignup             *bool
	SsoSessionIdleTimeout       *string
	TrustDeviceEnabled          *bool
	TrustDeviceExpiration       *string
}

// getEnv returns the value of the environment variable or the fallback.
func getEnv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

// getEnvBool parses a boolean environment variable with a fallback.
func getEnvBool(key string, fallback bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}

// getEnvFloat parses a float64 environment variable with a fallback.
func getEnvFloat(key string, fallback float64) float64 {
	v, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return fallback
	}
	return f
}

// getEnvInt parses an int environment variable with a fallback.
func getEnvInt(key string, fallback int) int {
	v, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}
