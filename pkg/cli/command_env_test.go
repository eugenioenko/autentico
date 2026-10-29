package cli

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db/migrations"
	"github.com/eugenioenko/autentico/pkg/totpsecret"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v2"
)

func TestManagementCommandsEnvFile(t *testing.T) {
	for _, command := range []struct {
		name string
		run  func(*cli.Context) error
	}{
		{name: "migrate", run: RunMigrate},
		{name: "onboard", run: RunOnboard},
	} {
		t.Run(command.name, func(t *testing.T) {
			for _, tt := range []struct {
				name        string
				path        string
				absolute    bool
				environment bool
				wantError   string
			}{
				{name: "optional default", wantError: "AUTENTICO_TOTP_ENCRYPTION_KEY is required"},
				{name: "default file", path: ".env"},
				{name: "relative path", path: "custom.env"},
				{name: "absolute path", path: "custom.env", absolute: true},
				{name: "environment wins", path: "custom.env", environment: true},
				{name: "missing file", path: "missing.env", wantError: "failed to load env file"},
				{name: "malformed file", path: "invalid.env", wantError: "failed to load env file"},
				{name: "directory", path: "directory", wantError: "failed to load env file"},
			} {
				t.Run(tt.name, func(t *testing.T) {
					dir := t.TempDir()
					t.Chdir(dir)
					testutils.WithConfigOverride(t, func() {})
					for _, key := range []string{"AUTENTICO_DB_FILE_PATH", totpsecret.EnvName, "AUTENTICO_APP_OAUTH_PATH"} {
						t.Setenv(key, "")
						require.NoError(t, os.Unsetenv(key))
					}
					t.Setenv("AUTENTICO_TRUSTED_PROXIES", "")
					key, err := totpsecret.GenerateKey()
					require.NoError(t, err)

					set := flag.NewFlagSet(command.name, flag.ContinueOnError)
					set.String("env-file", "", "")
					set.Var(cli.NewIntSlice(15, 17), "approve-major", "")
					set.String("username", "admin", "")
					set.String("password", "password123", "")
					path := tt.path
					if tt.absolute {
						path = filepath.Join(dir, path)
					}
					if path != "" && path != ".env" {
						require.NoError(t, set.Set("env-file", path))
						// Unrelated CWD settings must never leak into selected configuration.
						require.NoError(t, os.WriteFile(".env", []byte("AUTENTICO_DB_FILE_PATH=unrelated.db\nAUTENTICO_TOTP_ENCRYPTION_KEY=invalid\nAUTENTICO_APP_OAUTH_PATH=/unrelated\n"), 0600))
					}
					wantDB := "selected.db"
					if tt.wantError == "" {
						content := fmt.Sprintf("AUTENTICO_DB_FILE_PATH=selected.db\nAUTENTICO_TOTP_ENCRYPTION_KEY=%s\n", key)
						if tt.environment {
							content = "AUTENTICO_DB_FILE_PATH=file.db\nAUTENTICO_TOTP_ENCRYPTION_KEY=invalid\n"
							wantDB = "process.db"
							t.Setenv("AUTENTICO_DB_FILE_PATH", wantDB)
							t.Setenv(totpsecret.EnvName, key)
						}
						require.NoError(t, os.WriteFile(path, []byte(content), 0600))
					} else if tt.name == "malformed file" {
						require.NoError(t, os.WriteFile(path, []byte("AUTENTICO_DB_FILE_PATH=\"unterminated"), 0600))
					} else if tt.name == "directory" {
						require.NoError(t, os.Mkdir(path, 0700))
					}

					err = command.run(cli.NewContext(&cli.App{}, set, nil))
					if tt.wantError != "" {
						require.ErrorContains(t, err, tt.wantError)
						require.NoFileExists(t, wantDB)
					} else {
						require.NoError(t, err)
						require.Equal(t, wantDB, config.GetBootstrap().DbFilePath)
						require.Equal(t, key, config.GetBootstrap().TotpEncryptionKey)
						require.Equal(t, "/oauth2", config.GetBootstrap().AppOAuthPath)
						version, _, err := migrations.InspectFile(wantDB)
						require.NoError(t, err)
						require.Equal(t, migrations.SchemaVersion, version)
					}
					for _, other := range []string{"autentico.db", "unrelated.db", "file.db"} {
						require.NoFileExists(t, other)
					}
				})
			}
		})
	}
}
