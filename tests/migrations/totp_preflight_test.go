package migrationstest

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/totpsecret"
	"github.com/stretchr/testify/require"
)

func TestRoutineUpgradeRejectsWrongTotpKeyBeforeChangingSchema(t *testing.T) {
	wrongKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{99}, 32))
	for _, version := range []int{17, 18} {
		for _, journal := range []string{"DELETE", "WAL"} {
			for _, entry := range []string{"start", "interactive", "unattended"} {
				t.Run(fmt.Sprintf("v%d/%s/%s", version, journal, entry), func(t *testing.T) {
					path, database := fixture(t, version, journal, false)
					sealed, err := totpsecret.Seal(totpKey, "enrolled", "JBSWY3DPEHPK3PXP")
					require.NoError(t, err)
					_, err = database.Exec(`INSERT INTO users(id,username,totp_secret,totp_verified,totp_last_used_step,totp_failed_attempts) VALUES('enrolled','enrolled',?,TRUE,42,3)`, sealed)
					require.NoError(t, err)
					require.NoError(t, database.Close())
					before := digest(t, path)
					args := []string{"migrate", "--approve-major=17"}
					input := ""
					switch entry {
					case "start":
						args = []string{"start"}
					case "interactive":
						args = []string{"migrate"}
						input = fmt.Sprintf("%d\n", target)
					}
					ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
					defer cancel()
					cmd := exec.CommandContext(ctx, binary, args...)
					cmd.Dir = filepath.Dir(path)
					cmd.Stdin = strings.NewReader(input)
					for _, value := range env(path) {
						if !strings.HasPrefix(value, totpsecret.EnvName+"=") {
							cmd.Env = append(cmd.Env, value)
						}
					}
					cmd.Env = append(cmd.Env, totpsecret.EnvName+"="+wrongKey)
					output, err := cmd.CombinedOutput()
					require.NoError(t, ctx.Err(), "CLI timed out")
					require.Error(t, err, string(output))
					require.Contains(t, string(output), "cannot decrypt TOTP secret")
					require.Contains(t, string(output), totpsecret.EnvName)
					require.NotContains(t, string(output), wrongKey)
					require.NotContains(t, string(output), "Applying migration")
					require.Equal(t, version, schema(t, path))
					if entry != "start" {
						require.Equal(t, before, digest(t, path), "migrate must leave the database unchanged")
					}
					database = openDB(t, path)
					var stored string
					var verified bool
					var step int64
					var attempts int
					require.NoError(t, database.QueryRow(`SELECT totp_secret,totp_verified,totp_last_used_step,totp_failed_attempts FROM users WHERE id='enrolled'`).Scan(&stored, &verified, &step, &attempts))
					require.Equal(t, sealed, stored)
					require.True(t, verified)
					require.EqualValues(t, 42, step)
					require.Equal(t, 3, attempts)
					var federationTable int
					require.NoError(t, database.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='federation_login_flows'`).Scan(&federationTable))
					require.Zero(t, federationTable)
					require.NoError(t, database.Close())
					require.Empty(t, backups(t, path))
					noRecovery(t, path)
					// Restoring the original key is sufficient; no restore/reset/re-enrollment.
					if entry == "start" {
						_, stop := startTotpServer(t, path)
						stop()
					} else {
						output, err := command(t, path, input, args...)
						require.NoError(t, err, output)
					}
					require.Equal(t, target, schema(t, path))
					database = openDB(t, path)
					require.NoError(t, database.QueryRow(`SELECT totp_secret FROM users WHERE id='enrolled'`).Scan(&stored))
					require.Equal(t, sealed, stored)
				})
			}
		}
	}
}
