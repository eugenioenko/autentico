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

	seedAdminClient()
	seedAccountClient()

	c1, err := client.ClientByClientID("autentico-admin")
	assert.NoError(t, err)
	assert.NotNil(t, c1)

	c2, err := client.ClientByClientID("autentico-account")
	assert.NoError(t, err)
	assert.NotNil(t, c2)

	// Test idempotent seeding
	seedAdminClient()
	seedAccountClient()
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
	seedAdminClient()
	seedAccountClient()
}
