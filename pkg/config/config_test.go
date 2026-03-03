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
	assert.Equal(t, false, Bootstrap.AuthIdpSessionSecureCookie)
	assert.Equal(t, false, Bootstrap.AuthCSRFSecureCookie)
}

func TestInitBootstrap_EnvOverride(t *testing.T) {
	saved := Bootstrap
	t.Cleanup(func() { Bootstrap = saved })

	t.Setenv("AUTENTICO_APP_URL", "https://example.com")
	t.Setenv("AUTENTICO_APP_OAUTH_PATH", "/auth")

	InitBootstrap()

	assert.Equal(t, "https://example.com", Bootstrap.AppURL)
	assert.Equal(t, "/auth", Bootstrap.AppOAuthPath)
	assert.Equal(t, "example.com", Bootstrap.AppDomain)
	assert.Equal(t, "https://example.com/auth", Bootstrap.AppAuthIssuer)
	assert.Equal(t, "443", Bootstrap.AppPort)
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

	exp := "1h"
	cfg := GetForClient(ClientOverrides{AccessTokenExpiration: &exp})
	assert.Equal(t, time.Hour, cfg.AuthAccessTokenExpiration)
}
