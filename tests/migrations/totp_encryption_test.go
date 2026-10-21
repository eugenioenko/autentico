package migrationstest

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/totpsecret"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func commandWithTotpKey(t *testing.T, path, key string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir = filepath.Dir(path)
	for _, value := range env(path) {
		if !strings.HasPrefix(value, totpsecret.EnvName+"=") {
			cmd.Env = append(cmd.Env, value)
		}
	}
	cmd.Env = append(cmd.Env, totpsecret.EnvName+"="+key)
	output, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "CLI timed out: %s", output)
	return string(output), err
}

func TestTotpMigrationMissingOrInvalidKeyDoesNotTouchDatabase(t *testing.T) {
	for _, version := range []int{14, 16} {
		for _, journal := range []string{"DELETE", "WAL"} {
			for _, key := range []string{"", "invalid-key-material"} {
				t.Run(fmt.Sprintf("v%d/%s/key=%t", version, journal, key != ""), func(t *testing.T) {
					path, database := fixture(t, version, journal, version < 15)
					require.NoError(t, database.Close())
					before := digest(t, path)
					output, err := commandWithTotpKey(t, path, key, "migrate", "--approve-major=15,17")
					require.Error(t, err, output)
					require.Contains(t, output, totpsecret.EnvName)
					if key == "" {
						require.Contains(t, output, "is required")
					} else {
						require.NotContains(t, output, key)
					}
					require.Equal(t, before, digest(t, path))
					require.Equal(t, version, schema(t, path))
					require.Empty(t, backups(t, path))
					noRecovery(t, path)
				})
			}
		}
	}
}

func TestTotpMigrationPreservesEnrollmentAndCodesAcrossRestart(t *testing.T) {
	for _, journal := range []string{"DELETE", "WAL"} {
		t.Run(journal, func(t *testing.T) {
			path, database := fixture(t, 16, journal, false)
			const seed = "JBSWY3DPEHPK3PXP"
			hash, err := bcrypt.GenerateFromPassword([]byte("Password123!"), bcrypt.MinCost)
			require.NoError(t, err)
			_, err = database.Exec(`INSERT INTO users(id,username,password,totp_secret,totp_verified,two_factor_enabled,totp_last_used_step,totp_failed_attempts)
				VALUES('active','active',?,?,TRUE,TRUE,123,2),('pending','pending','',?,FALSE,FALSE,-1,0),('deactivated','deactivated','',?,TRUE,TRUE,12,0),('empty','empty','','',FALSE,FALSE,-1,0)`, string(hash), seed, seed, seed)
			require.NoError(t, err)
			_, err = database.Exec(`UPDATE users SET deactivated_at=CURRENT_TIMESTAMP WHERE id='deactivated';
				INSERT INTO clients(id,client_id,client_name,client_type,redirect_uris,post_logout_redirect_uris,grant_types,scopes,is_active)
				VALUES('totp-client','totp-client','Migration test','public','[]','[]','["password","refresh_token"]','openid profile email',TRUE)`)
			require.NoError(t, err)
			require.NoError(t, database.Close())
			output, err := command(t, path, "", "migrate", "--approve-major=17")
			require.NoError(t, err, output)
			require.Contains(t, output, "enrollments will be encrypted in place and preserved")
			require.Equal(t, 17, schema(t, path))
			require.Len(t, backups(t, path), 1)
			database = openDB(t, path)
			for _, id := range []string{"active", "pending", "deactivated"} {
				var stored string
				require.NoError(t, database.QueryRow(`SELECT totp_secret FROM users WHERE id=?`, id).Scan(&stored))
				require.NotEqual(t, seed, stored)
				plain, err := totpsecret.Open(totpKey, id, stored)
				require.NoError(t, err)
				require.Equal(t, seed, plain)
			}
			var verified, enabled bool
			var step int64
			var attempts int
			require.NoError(t, database.QueryRow(`SELECT totp_verified,two_factor_enabled,totp_last_used_step,totp_failed_attempts FROM users WHERE id='active'`).Scan(&verified, &enabled, &step, &attempts))
			require.True(t, verified)
			require.True(t, enabled)
			require.EqualValues(t, 123, step)
			require.Equal(t, 2, attempts)
			require.NoError(t, database.Close())
			rawDatabase, err := os.ReadFile(path)
			require.NoError(t, err)
			require.NotContains(t, string(rawDatabase), seed, "old plaintext seeds must not remain in the upgraded database pages")
			require.NotContains(t, string(rawDatabase), totpKey, "the encryption key must stay outside the database")
			before := digest(t, path)
			output, err = command(t, path, "", "migrate", "--approve-major=17")
			require.NoError(t, err, output)
			require.Equal(t, before, digest(t, path), "repeated migrate must not re-encrypt")
			code, err := totp.GenerateCode(seed, time.Now())
			require.NoError(t, err)
			base, stop := startTotpServer(t, path)
			post := func(base string) int {
				resp, err := http.PostForm(base+"/oauth2/token", url.Values{"grant_type": {"password"}, "client_id": {"totp-client"}, "username": {"active"}, "password": {"Password123!"}, "totp_code": {code}})
				require.NoError(t, err)
				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				require.NoError(t, resp.Body.Close())
				if resp.StatusCode != http.StatusOK {
					require.Contains(t, string(body), "invalid_mfa_code")
				}
				return resp.StatusCode
			}
			require.Equal(t, http.StatusOK, post(base), "the original authenticator still works after migration")
			stop()
			base, stop = startTotpServer(t, path)
			require.Equal(t, http.StatusForbidden, post(base), "restart must retain the consumed timestep")
			stop()
			beforeWrongKey := digest(t, path)
			wrongKey, err := totpsecret.GenerateKey()
			require.NoError(t, err)
			output, err = commandWithTotpKey(t, path, wrongKey, "migrate", "--approve-major=17")
			require.Error(t, err, output)
			require.Contains(t, output, "restore the original "+totpsecret.EnvName)
			require.Equal(t, beforeWrongKey, digest(t, path), "wrong-key attempts must not replace or disable enrollments")
			output, err = commandWithTotpKey(t, path, wrongKey, "start")
			require.Error(t, err, output)
			require.Contains(t, output, "restore the original "+totpsecret.EnvName)
		})
	}
}

func TestTotpEncryptionFailureRestoresPlaintextAndCanRetry(t *testing.T) {
	for _, journal := range []string{"DELETE", "WAL"} {
		for _, failure := range []string{"update", "commit"} {
			t.Run(journal+"/"+failure, func(t *testing.T) {
				path, database := fixture(t, 16, journal, false)
				_, err := database.Exec(`INSERT INTO users(id,username,totp_secret,totp_verified,totp_last_used_step)
				VALUES('a','a','FIRST-SEED',TRUE,22),('z','z','LAST-SEED',TRUE,33)`)
				require.NoError(t, err)
				if failure == "update" {
					_, err = database.Exec(`CREATE TRIGGER fail_totp BEFORE UPDATE OF totp_secret ON users WHEN OLD.id='z'
					BEGIN SELECT RAISE(ABORT,'injected encryption failure'); END`)
				} else {
					_, err = database.Exec(`CREATE TABLE parent(id INTEGER PRIMARY KEY);
					CREATE TABLE deferred_failure(id INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED);
					CREATE TRIGGER fail_totp AFTER UPDATE OF totp_secret ON users WHEN OLD.id='z'
					BEGIN INSERT INTO deferred_failure VALUES(1); END`)
				}
				require.NoError(t, err)
				require.NoError(t, database.Close())
				before := digest(t, path)
				output, err := command(t, path, "", "migrate", "--approve-major=17")
				require.Error(t, err, output)
				require.Contains(t, output, "restored schema v16")
				require.Equal(t, 16, schema(t, path))
				require.Equal(t, before, digest(t, path))
				noRecovery(t, path)
				database = openDB(t, path)
				var secret string
				require.NoError(t, database.QueryRow(`SELECT totp_secret FROM users WHERE id='a'`).Scan(&secret))
				require.Equal(t, "FIRST-SEED", secret, "an earlier row must not remain encrypted after rollback")
				_, err = database.Exec("DROP TRIGGER fail_totp")
				require.NoError(t, err)
				require.NoError(t, database.Close())
				output, err = command(t, path, "", "migrate", "--approve-major=17")
				require.NoError(t, err, output)
				require.Equal(t, 17, schema(t, path))
			})
		}
	}
}

func TestTotpEncryptionInterruptedUpgradeRecoversEnrollments(t *testing.T) {
	path, database := fixture(t, 16, "WAL", false)
	_, err := database.Exec(`INSERT INTO users(id,username,totp_secret,totp_verified) VALUES('u','u','ORIGINAL-SEED',TRUE);
		CREATE TRIGGER slow_totp BEFORE UPDATE OF totp_secret ON users BEGIN
		SELECT sum(x) FROM (WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<5000000) SELECT x FROM n); END`)
	require.NoError(t, err)
	require.NoError(t, database.Close())
	cmd, output := runUntil(t, path, "Applying migration v17")
	require.NoError(t, cmd.Process.Kill())
	require.Error(t, cmd.Wait(), output.String())
	text, err := commandWithTotpKey(t, path, "", "migrate", "--approve-major=17")
	require.Error(t, err, text)
	require.Contains(t, text, totpsecret.EnvName+" is required")
	_, err = os.Stat(path + ".migration.json")
	require.NoError(t, err, "missing-key refusal must not discard the recovery record")
	text, err = command(t, path, "", "start")
	require.Error(t, err, text)
	require.Contains(t, text, "interrupted major migration")
	text, err = command(t, path, "cancel\n", "migrate")
	require.NoError(t, err, text)
	require.Contains(t, text, "Restored pre-migration database")
	require.Equal(t, 16, schema(t, path))
	noRecovery(t, path)
	database = openDB(t, path)
	var stored string
	var verified bool
	require.NoError(t, database.QueryRow(`SELECT totp_secret,totp_verified FROM users WHERE id='u'`).Scan(&stored, &verified))
	require.Equal(t, "ORIGINAL-SEED", stored)
	require.True(t, verified)
	_, err = database.Exec("DROP TRIGGER slow_totp")
	require.NoError(t, err)
	require.NoError(t, database.Close())
	text, err = command(t, path, "", "migrate", "--approve-major=17")
	require.NoError(t, err, text)
	require.Equal(t, 17, schema(t, path))
}

func TestTotpRecoveryDiscardsHotDeleteJournalAfterCommittedMigration(t *testing.T) {
	path, database := fixture(t, 15, "DELETE", false)
	// Persist a small default page cache so the child migrator spills dirty
	// pages before COMMIT, creating a genuinely hot rollback journal.
	_, err := database.Exec(`PRAGMA default_cache_size=1;
		WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<2000)
		INSERT INTO users(id,username,totp_secret,totp_verified)
		SELECT printf('user-%04d',x),printf('user-%04d',x),'JBSWY3DPEHPK3PXP',TRUE FROM n;
		CREATE TRIGGER slow_totp AFTER UPDATE OF totp_secret ON users WHEN OLD.id='user-2000' BEGIN
		SELECT sum(x) FROM (WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<10000000) SELECT x FROM n); END`)
	require.NoError(t, err)
	require.NoError(t, database.Close())
	original := digest(t, path)
	cmd, output := runUntil(t, path, "Applying migration v17")
	// Schema 16 has committed, but schema 17 is still uncommitted. A nonzero
	// journal header proves this is not merely an empty journal placeholder.
	magic := []byte{0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7}
	deadline := time.Now().Add(10 * time.Second)
	for {
		journal, err := os.ReadFile(path + "-journal")
		if err == nil && len(journal) > 512 && bytes.Equal(journal[:8], magic) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("did not observe a hot rollback journal: " + output.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	require.NoError(t, cmd.Process.Kill())
	require.Error(t, cmd.Wait(), output.String())
	journal, err := os.ReadFile(path + "-journal")
	require.NoError(t, err)
	require.True(t, bytes.Equal(journal[:8], magic))
	// Do not open the live database before recovery: SQLite would replay the
	// journal and hide the stale-journal/snapshot replacement regression.
	text, err := command(t, path, "cancel\n", "migrate")
	require.NoError(t, err, text)
	require.Contains(t, text, "Restored pre-migration database")
	require.Equal(t, original, digest(t, path), "recovery must restore the original schema-15 snapshot byte for byte")
	require.Equal(t, 15, schema(t, path), "a stale journal must not restore the intermediate schema 16")
	_, err = os.Stat(path + "-journal")
	require.True(t, os.IsNotExist(err))
	noRecovery(t, path)
	database = openDB(t, path)
	var count int
	require.NoError(t, database.QueryRow(`SELECT count(*) FROM users WHERE totp_secret='JBSWY3DPEHPK3PXP' AND totp_verified=TRUE`).Scan(&count))
	require.Equal(t, 2000, count)
	require.NoError(t, database.QueryRow(`SELECT count(*) FROM pragma_table_info('users') WHERE name='totp_last_used_step'`).Scan(&count))
	require.Zero(t, count)
	_, err = database.Exec(`DROP TRIGGER slow_totp; PRAGMA default_cache_size=2000`)
	require.NoError(t, err)
	require.NoError(t, database.Close())
	text, err = command(t, path, "", "migrate", "--approve-major=17")
	require.NoError(t, err, text)
	require.Equal(t, 17, schema(t, path))
	database = openDB(t, path)
	require.NoError(t, database.QueryRow(`SELECT count(*) FROM users WHERE totp_secret LIKE 'totp:v1:%' AND totp_verified=TRUE`).Scan(&count))
	require.Equal(t, 2000, count)
}

func startTotpServer(t *testing.T, path string) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	require.NoError(t, listener.Close())
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	cmd := exec.CommandContext(ctx, binary, "start")
	cmd.Dir = filepath.Dir(path)
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	cmd.Env = append(env(path), fmt.Sprintf("AUTENTICO_LISTEN_PORT=%d", port), "AUTENTICO_APP_URL="+base, "AUTENTICO_RATE_LIMIT_RPS=0", "AUTENTICO_RATE_LIMIT_RPM=0")
	var output lockedBuffer
	cmd.Stdout, cmd.Stderr = &output, &output
	require.NoError(t, cmd.Start())
	stopped := false
	stop := func() {
		if !stopped {
			stopped = true
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			cancel()
		}
	}
	t.Cleanup(stop)
	client := &http.Client{Timeout: time.Second}
	for {
		resp, err := client.Get(base + "/.well-known/openid-configuration")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return base, stop
			}
		}
		select {
		case <-ctx.Done():
			t.Fatal(output.String())
		case <-time.After(20 * time.Millisecond):
		}
	}
}
