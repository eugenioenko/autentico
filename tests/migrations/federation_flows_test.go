package migrationstest

import (
	"fmt"
	"testing"

	"github.com/eugenioenko/autentico/pkg/totpsecret"
	"github.com/stretchr/testify/require"
)

func TestFederationFlowRoutineUpgradePreservesExistingCredentials(t *testing.T) {
	for _, journal := range []string{"DELETE", "WAL"} {
		for _, mode := range []string{"migrate", "start"} {
			t.Run(journal+"/"+mode, func(t *testing.T) {
				path, database := fixture(t, 18, journal, false)
				ciphertext, err := totpsecret.Seal(totpKey, "kept", "JBSWY3DPEHPK3PXP")
				require.NoError(t, err)
				_, err = database.Exec(`INSERT INTO users(id,username,password,totp_secret,totp_verified,totp_last_used_step,totp_failed_attempts) VALUES('kept','kept','kept-password',?,TRUE,123,2);
INSERT INTO tokens(id,user_id,access_token_hash,refresh_token_hash,access_token_type,refresh_token_expires_at,access_token_expires_at,scope,grant_type) VALUES('kept-token','kept','access-hash','refresh-hash','Bearer',datetime('now','+1 day'),datetime('now','+1 hour'),'openid','password');
INSERT INTO sessions(id,user_id,access_token_hash,refresh_token_hash) VALUES('kept-session','kept','access-hash','refresh-hash');
INSERT INTO idp_sessions(id,user_id,mfa_method,user_agent) VALUES('kept-idp','kept','totp','kept browser');
INSERT INTO trusted_devices(id,user_id,expires_at) VALUES('kept-device','kept',datetime('now','+1 day'))`, ciphertext)
				require.NoError(t, err)
				require.NoError(t, database.Close())
				if mode == "migrate" {
					output, err := command(t, path, fmt.Sprintf("%d\n", target), "migrate")
					require.NoError(t, err, output)
					require.Contains(t, output, "Migration v19 applied")
					require.NotContains(t, output, "Everyone must sign in again")
				} else {
					_, stop := startTotpServer(t, path)
					stop()
				}
				require.Equal(t, target, schema(t, path))
				require.Empty(t, backups(t, path))
				noRecovery(t, path)
				database = openDB(t, path)
				var secret, password, accessHash, refreshHash, method, agent string
				var verified bool
				var step int64
				var attempts int
				require.NoError(t, database.QueryRow(`SELECT password,totp_secret,totp_verified,totp_last_used_step,totp_failed_attempts FROM users WHERE id='kept'`).Scan(&password, &secret, &verified, &step, &attempts))
				require.Equal(t, "kept-password", password)
				require.Equal(t, ciphertext, secret, "routine upgrade must not rewrite an enrollment")
				require.True(t, verified)
				require.EqualValues(t, 123, step)
				require.Equal(t, 2, attempts)
				require.NoError(t, database.QueryRow(`SELECT access_token_hash,refresh_token_hash FROM tokens WHERE id='kept-token'`).Scan(&accessHash, &refreshHash))
				require.Equal(t, "access-hash", accessHash)
				require.Equal(t, "refresh-hash", refreshHash)
				require.NoError(t, database.QueryRow(`SELECT access_token_hash,refresh_token_hash FROM sessions WHERE id='kept-session'`).Scan(&accessHash, &refreshHash))
				require.Equal(t, "access-hash", accessHash)
				require.Equal(t, "refresh-hash", refreshHash)
				require.NoError(t, database.QueryRow(`SELECT mfa_method,user_agent FROM idp_sessions WHERE id='kept-idp'`).Scan(&method, &agent))
				require.Equal(t, "totp", method)
				require.Equal(t, "kept browser", agent)
				var count int
				require.NoError(t, database.QueryRow(`SELECT COUNT(*) FROM trusted_devices WHERE id='kept-device'`).Scan(&count))
				require.Equal(t, 1, count)
				require.NoError(t, database.QueryRow(`SELECT COUNT(*) FROM federation_login_flows`).Scan(&count))
				require.Zero(t, count)
				require.NoError(t, database.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_federation_login_flows_expiry'`).Scan(&count))
				require.Equal(t, 1, count)
			})
		}
	}
}

func TestFederationFlowRoutineMigrationRollsBackPartialDDL(t *testing.T) {
	for _, journal := range []string{"DELETE", "WAL"} {
		for _, mode := range []string{"migrate", "start"} {
			t.Run(journal+"/"+mode, func(t *testing.T) {
				path, database := fixture(t, 18, journal, false)
				// The index collision fails the second statement, after the flow table
				// was created. A routine upgrade must roll back both DDL and version.
				_, err := database.Exec(`INSERT INTO users(id,username,password) VALUES('kept','kept','kept-password'); CREATE TABLE index_collision(id INTEGER); CREATE INDEX idx_federation_login_flows_expiry ON index_collision(id)`)
				require.NoError(t, err)
				require.NoError(t, database.Close())
				input := ""
				if mode == "migrate" {
					input = fmt.Sprintf("%d\n", target)
				}
				output, err := command(t, path, input, mode)
				require.Error(t, err, output)
				require.Contains(t, output, "idx_federation_login_flows_expiry")
				require.Equal(t, 18, schema(t, path))
				require.Empty(t, backups(t, path))
				noRecovery(t, path)
				database = openDB(t, path)
				var count int
				require.NoError(t, database.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='federation_login_flows'`).Scan(&count))
				require.Zero(t, count, "partial DDL must be rolled back")
				var password string
				require.NoError(t, database.QueryRow(`SELECT password FROM users WHERE id='kept'`).Scan(&password))
				require.Equal(t, "kept-password", password)
				_, err = database.Exec(`DROP INDEX idx_federation_login_flows_expiry`)
				require.NoError(t, err)
				require.NoError(t, database.Close())
				output, err = command(t, path, fmt.Sprintf("%d\n", target), "migrate")
				require.NoError(t, err, output)
				require.Equal(t, target, schema(t, path))
				database = openDB(t, path)
				require.NoError(t, database.QueryRow(`SELECT COUNT(*) FROM federation_login_flows`).Scan(&count))
				require.Zero(t, count)
				require.NoError(t, database.QueryRow(`SELECT password FROM users WHERE id='kept'`).Scan(&password))
				require.Equal(t, "kept-password", password)
			})
		}
	}
}
