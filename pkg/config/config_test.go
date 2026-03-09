package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGet(t *testing.T) {
	cfg := Get()
	assert.NotNil(t, cfg)
	assert.Equal(t, &Values, cfg)
}

func TestGetOriginal(t *testing.T) {
	original := GetOriginal()
	assert.Equal(t, 15*time.Minute, original.AuthAccessTokenExpiration)
	assert.Equal(t, false, original.AuthAllowSelfSignup)
	assert.Equal(t, "password", original.AuthMode)
}

func TestDefaultConfig(t *testing.T) {
	assert.Equal(t, false, defaultConfig.TrustDeviceEnabled)
	assert.Equal(t, false, defaultConfig.RequireMfa)
	assert.Equal(t, time.Duration(0), defaultConfig.AuthSsoSessionIdleTimeout)
	assert.Equal(t, "0", defaultConfig.AuthSsoSessionIdleTimeoutStr)
	assert.Equal(t, 15*time.Minute, defaultConfig.AuthAccessTokenExpiration)
}

func TestInitBootstrap_Defaults(t *testing.T) {
	saved := Bootstrap
	t.Cleanup(func() { Bootstrap = saved })

	InitBootstrap()

	assert.Equal(t, "http://localhost:9999", Bootstrap.AppURL)
	assert.Equal(t, "/oauth2", Bootstrap.AppOAuthPath)
	assert.Equal(t, "localhost", Bootstrap.AppDomain)
	assert.Equal(t, "localhost:9999", Bootstrap.AppHost)
	assert.Equal(t, "9999", Bootstrap.AppPort)
	assert.Equal(t, "http://localhost:9999/oauth2", Bootstrap.AppAuthIssuer)
	assert.Equal(t, "autentico-key-1", Bootstrap.AuthJwkCertKeyID)
	assert.Equal(t, "autentico_idp_session", Bootstrap.AuthIdpSessionCookieName)
	assert.Equal(t, true, Bootstrap.AuthIdpSessionSecureCookie)
	assert.Equal(t, true, Bootstrap.AuthCSRFSecureCookie)
}

func TestInitBootstrap_EnvOverride(t *testing.T) {
	saved := Bootstrap
	t.Cleanup(func() { Bootstrap = saved })

	t.Setenv("AUTENTICO_APP_URL", "https://example.com")
	t.Setenv("AUTENTICO_APP_OAUTH_PATH", "/auth")
	t.Setenv("AUTENTICO_LISTEN_PORT", "8080")
	t.Setenv("AUTENTICO_APP_ENABLE_CORS", "false")
	t.Setenv("AUTENTICO_RATE_LIMIT_RPS", "10.5")
	t.Setenv("AUTENTICO_RATE_LIMIT_BURST", "20")

	InitBootstrap()

	assert.Equal(t, "https://example.com", Bootstrap.AppURL)
	assert.Equal(t, "/auth", Bootstrap.AppOAuthPath)
	assert.Equal(t, "example.com", Bootstrap.AppDomain)
	assert.Equal(t, "https://example.com/auth", Bootstrap.AppAuthIssuer)
	assert.Equal(t, "443", Bootstrap.AppPort)
	assert.Equal(t, "8080", Bootstrap.AppListenPort)
	assert.Equal(t, false, Bootstrap.AppEnableCORS)
	assert.Equal(t, 10.5, Bootstrap.RateLimitRPS)
	assert.Equal(t, 20, Bootstrap.RateLimitBurst)
}

func TestParseDuration(t *testing.T) {
	assert.Equal(t, 15*time.Minute, ParseDuration("15m", time.Hour))
	assert.Equal(t, time.Hour, ParseDuration("invalid", time.Hour))
	assert.Equal(t, time.Hour, ParseDuration("", time.Hour))
}

func TestGetForClient_NoOverrides(t *testing.T) {
	saved := Values
	t.Cleanup(func() { Values = saved })
	Values.AuthAccessTokenExpiration = 30 * time.Minute

	cfg := GetForClient(ClientOverrides{})
	assert.Equal(t, 30*time.Minute, cfg.AuthAccessTokenExpiration)
}

func TestGetForClient_WithOverrides(t *testing.T) {
	saved := Values
	t.Cleanup(func() { Values = saved })
	Values.AuthAccessTokenExpiration = 30 * time.Minute
	Values.AuthAllowSelfSignup = false

	exp := "1h"
	rexp := "24h"
	aexp := "5m"
	signup := true
	sso := "30m"
	trust := true
	trustExp := "48h"
	
	cfg := GetForClient(ClientOverrides{
		AccessTokenExpiration:       &exp,
		RefreshTokenExpiration:      &rexp,
		AuthorizationCodeExpiration: &aexp,
		AllowedAudiences:            []string{"aud1"},
		AllowSelfSignup:             &signup,
		SsoSessionIdleTimeout:       &sso,
		TrustDeviceEnabled:          &trust,
		TrustDeviceExpiration:       &trustExp,
	})
	
	assert.Equal(t, time.Hour, cfg.AuthAccessTokenExpiration)
	assert.Equal(t, 24*time.Hour, cfg.AuthRefreshTokenExpiration)
	assert.Equal(t, 5*time.Minute, cfg.AuthAuthorizationCodeExpiration)
	assert.Equal(t, []string{"aud1"}, cfg.AuthAccessTokenAudience)
	assert.True(t, cfg.AuthAllowSelfSignup)
	assert.Equal(t, 30*time.Minute, cfg.AuthSsoSessionIdleTimeout)
	assert.True(t, cfg.TrustDeviceEnabled)
	assert.Equal(t, 48*time.Hour, cfg.TrustDeviceExpiration)
}

func TestGetEnvHelpers(t *testing.T) {
	t.Setenv("TEST_BOOL", "true")
	assert.True(t, getEnvBool("TEST_BOOL", false))
	assert.True(t, getEnvBool("NONEXISTENT", true))
	t.Setenv("TEST_BOOL_INVALID", "not-a-bool")
	assert.True(t, getEnvBool("TEST_BOOL_INVALID", true))

	t.Setenv("TEST_FLOAT", "1.5")
	assert.Equal(t, 1.5, getEnvFloat("TEST_FLOAT", 0.0))
	assert.Equal(t, 2.5, getEnvFloat("NONEXISTENT", 2.5))
	t.Setenv("TEST_FLOAT_INVALID", "not-a-float")
	assert.Equal(t, 3.5, getEnvFloat("TEST_FLOAT_INVALID", 3.5))

	t.Setenv("TEST_INT", "10")
	assert.Equal(t, 10, getEnvInt("TEST_INT", 0))
	assert.Equal(t, 20, getEnvInt("NONEXISTENT", 20))
	t.Setenv("TEST_INT_INVALID", "not-an-int")
	assert.Equal(t, 30, getEnvInt("TEST_INT_INVALID", 30))
}
