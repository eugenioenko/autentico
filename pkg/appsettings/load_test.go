package appsettings

import (
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
)

func TestEnsureDefaults(t *testing.T) {
	testutils.WithTestDB(t)

	// Defaults should be empty initially in a fresh test DB (Wait, WithTestDB runs migrations but not app-level seeds usually)
	// Actually EnsureDefaults is what we are testing.

	err := EnsureDefaults()
	assert.NoError(t, err)

	val, err := GetSetting("access_token_expiration")
	assert.NoError(t, err)
	assert.Equal(t, "15m", val)

	// Change a value and ensure it's not overwritten
	err = SetSetting("access_token_expiration", "30m")
	assert.NoError(t, err)

	err = EnsureDefaults()
	assert.NoError(t, err)

	val, err = GetSetting("access_token_expiration")
	assert.NoError(t, err)
	assert.Equal(t, "30m", val)
}

func TestLoadIntoConfig(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		// Set some values in DB
		_ = SetSetting("access_token_expiration", "45m")
		_ = SetSetting("allow_self_signup", "true")
		_ = SetSetting("validation_min_username_length", "10")
		_ = SetSetting("access_token_audience", `["aud1", "aud2"]`)

		err := LoadIntoConfig()
		assert.NoError(t, err)

		cfg := config.Get()
		assert.Equal(t, 45*time.Minute, cfg.AuthAccessTokenExpiration)
		assert.Equal(t, "45m", cfg.AuthAccessTokenExpirationStr)
		assert.True(t, cfg.AuthAllowSelfSignup)
		assert.Equal(t, 10, cfg.ValidationMinUsernameLength)
		assert.Equal(t, []string{"aud1", "aud2"}, cfg.AuthAccessTokenAudience)
	})
}

func TestParseBool(t *testing.T) {
	assert.True(t, parseBool("true", false))
	assert.True(t, parseBool("1", false))
	assert.False(t, parseBool("false", true))
	assert.False(t, parseBool("invalid", false))
}
