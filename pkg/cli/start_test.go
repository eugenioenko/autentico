package cli

import (
	"flag"
	"os"
	"testing"

	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/urfave/cli/v2"
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

func TestRunStart_DbPanic(t *testing.T) {
	// Set an invalid DB path in environment
	origPath := os.Getenv("AUTENTICO_DB_FILE")
	_ = os.Setenv("AUTENTICO_DB_FILE", "/nonexistent/path/db.sqlite")
	defer func() { _ = os.Setenv("AUTENTICO_DB_FILE", origPath) }()

	app := &cli.App{Name: "test"}
	ctx := cli.NewContext(app, flag.NewFlagSet("test", flag.ContinueOnError), nil)

	// Since db.InitDB panics on error during busy timeout set
	assert.Panics(t, func() {
		_ = RunStart(ctx)
	})
}

func TestSeedClients_Errors(t *testing.T) {
	testutils.WithTestDB(t)
	
	// Close DB to trigger errors in seeding
	db.CloseDB()
	
	// These should not panic but will log warnings
	seedAdminClient()
	seedAccountClient()
}
