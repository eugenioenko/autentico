package cli

import (
	"testing"

	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
)

func TestSeedClients(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AppURL = "http://test.com"
	})

	seedAdminClient(false)
	seedAccountClient()

	c1, err := client.ClientByClientID("autentico-admin")
	assert.NoError(t, err)
	assert.NotNil(t, c1)
	assert.NotContains(t, c1.GetGrantTypes(), "password", "default seed must not include password grant")

	c2, err := client.ClientByClientID("autentico-account")
	assert.NoError(t, err)
	assert.NotNil(t, c2)

	// Test idempotent seeding
	seedAdminClient(false)
	seedAccountClient()
}

func TestSeedAdminClient_WithPasswordGrant(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AppURL = "http://test.com"
	})

	seedAdminClient(true)

	c, err := client.ClientByClientID("autentico-admin")
	assert.NoError(t, err)
	assert.NotNil(t, c)
	grants := c.GetGrantTypes()
	assert.Contains(t, grants, "password", "password grant must be present when enabled")
	assert.Contains(t, grants, "authorization_code")
	assert.Contains(t, grants, "refresh_token")
}

func TestValidateBootstrapSecrets_MissingAll(t *testing.T) {
	bs := &config.BootstrapConfig{}
	err := validateBootstrapSecrets(bs)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing required secrets")
}

func TestValidateBootstrapSecrets_MissingOne(t *testing.T) {
	bs := &config.BootstrapConfig{
		AuthAccessTokenSecret:       "secret1",
		AuthRefreshTokenSecret:      "",
		AuthCSRFProtectionSecretKey: "secret3",
	}
	err := validateBootstrapSecrets(bs)
	assert.Error(t, err)
}

func TestValidateBootstrapSecrets_AllSet(t *testing.T) {
	bs := &config.BootstrapConfig{
		AuthAccessTokenSecret:       "secret1",
		AuthRefreshTokenSecret:      "secret2",
		AuthCSRFProtectionSecretKey: "secret3",
	}
	err := validateBootstrapSecrets(bs)
	assert.NoError(t, err)
}

func TestSeedClients_Errors(t *testing.T) {
	testutils.WithTestDB(t)
	
	// Close DB to trigger errors in seeding
	db.CloseDB()
	
	// These should not panic but will log warnings
	seedAdminClient(false)
	seedAccountClient()
}
