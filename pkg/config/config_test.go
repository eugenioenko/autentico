package config

import (
	"os"
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
	assert.Equal(t, "localhost", original.AppDomain)
	assert.Equal(t, "9999", original.AppPort)
	assert.Equal(t, 15*time.Minute, original.AuthAccessTokenExpiration)
}

func TestInitConfig_FileNotFound(t *testing.T) {
	// Save and restore
	saved := Values

	err := InitConfig("nonexistent.json")
	assert.NoError(t, err) // no error, just uses defaults

	// Should have default values
	assert.Equal(t, "localhost", Values.AppDomain)
	assert.Equal(t, 15*time.Minute, Values.AuthAccessTokenExpiration)

	Values = saved
}

func TestInitConfig_ValidFile(t *testing.T) {
	saved := Values

	// Create a temp config file
	content := []byte(`{"appPort": "8080", "authAccessTokenExpiration": "30m"}`)
	tmpFile, err := os.CreateTemp("", "autentico-test-*.json")
	assert.NoError(t, err)
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	_, err = tmpFile.Write(content)
	assert.NoError(t, err)
	_ = tmpFile.Close()

	err = InitConfig(tmpFile.Name())
	assert.NoError(t, err)

	assert.Equal(t, "8080", Values.AppPort)
	assert.Equal(t, 30*time.Minute, Values.AuthAccessTokenExpiration)

	Values = saved
}

func TestInitConfig_InvalidDuration(t *testing.T) {
	saved := Values

	content := []byte(`{"authAccessTokenExpiration": "invalid"}`)
	tmpFile, err := os.CreateTemp("", "autentico-test-*.json")
	assert.NoError(t, err)
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	_, err = tmpFile.Write(content)
	assert.NoError(t, err)
	_ = tmpFile.Close()

	err = InitConfig(tmpFile.Name())
	assert.NoError(t, err)

	// Should fall back to default
	assert.Equal(t, 15*time.Minute, Values.AuthAccessTokenExpiration)

	Values = saved
}

func TestInitConfig_PartialOverride(t *testing.T) {
	saved := Values

	content := []byte(`{"appDomain": "example.com"}`)
	tmpFile, err := os.CreateTemp("", "autentico-test-*.json")
	assert.NoError(t, err)
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	_, err = tmpFile.Write(content)
	assert.NoError(t, err)
	_ = tmpFile.Close()

	err = InitConfig(tmpFile.Name())
	assert.NoError(t, err)

	assert.Equal(t, "example.com", Values.AppDomain)
	// Other values should remain defaults
	assert.Equal(t, "9999", Values.AppPort)

	Values = saved
}

func TestInitConfig_SsoSessionIdleTimeout(t *testing.T) {
	saved := Values

	content := []byte(`{"authSsoSessionIdleTimeout": "1h"}`)
	tmpFile, err := os.CreateTemp("", "autentico-test-*.json")
	assert.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.Write(content)
	assert.NoError(t, err)
	tmpFile.Close()

	err = InitConfig(tmpFile.Name())
	assert.NoError(t, err)

	assert.Equal(t, time.Hour, Values.AuthSsoSessionIdleTimeout)

	Values = saved
}

func TestDefaultConfig(t *testing.T) {
	assert.Equal(t, "localhost", defaultConfig.AppDomain)
	assert.Equal(t, "localhost:9999", defaultConfig.AppHost)
	assert.Equal(t, "9999", defaultConfig.AppPort)
	assert.Equal(t, false, defaultConfig.AuthCSRFSecureCookie)
	assert.Equal(t, "autentico_idp_session", defaultConfig.AuthIdpSessionCookieName)
	assert.Equal(t, false, defaultConfig.AuthIdpSessionSecureCookie)
	assert.Equal(t, time.Duration(0), defaultConfig.AuthSsoSessionIdleTimeout)
	assert.Equal(t, "0", defaultConfig.AuthSsoSessionIdleTimeoutStr)
}
