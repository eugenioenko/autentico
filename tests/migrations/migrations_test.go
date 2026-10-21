// Package migrationstest exercises the built CLI against real SQLite files.
// Historical SQL is used only to arrange old databases; all upgrades, approval,
// backups, recovery, and startup checks run in separate application processes.
package migrationstest

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/sqliteutil"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

const target = 16

var binary, root string

func TestMain(m *testing.M) {
	if os.Getenv("AUTENTICO_TEST_LIMIT_HELPER") == "1" {
		os.Exit(m.Run())
	}
	_, file, _, _ := runtime.Caller(0)
	root = filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
	dir, err := os.MkdirTemp("", "autentico-migration-binary-")
	if err != nil {
		panic(err)
	}
	binary = filepath.Join(dir, "autentico")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", binary, ".")
	cmd.Dir = root
	if output, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build migration CLI: %v\n%s", err, output)
		_ = os.RemoveAll(dir)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func openDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	u := sqliteutil.FileURL(path)
	u.RawQuery = "_pragma=foreign_keys(1)&_pragma=busy_timeout(1000)"
	db, err := sql.Open("sqlite", u.String())
	require.NoError(t, err)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func historicalSQL(t *testing.T, version int) string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(root, "pkg/db/migrations", fmt.Sprintf("%03d_*.go", version)))
	require.NoError(t, err)
	require.Len(t, matches, 1)
	f, err := parser.ParseFile(token.NewFileSet(), matches[0], nil, 0)
	require.NoError(t, err)
	var text string
	ast.Inspect(f, func(n ast.Node) bool {
		spec, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for i, name := range spec.Names {
			if name.Name == fmt.Sprintf("migration%03d", version) {
				lit, ok := spec.Values[i].(*ast.BasicLit)
				require.True(t, ok)
				text, err = strconv.Unquote(lit.Value)
				require.NoError(t, err)
			}
		}
		return true
	})
	require.NotEmpty(t, text)
	return text
}

// Both empty and populated installations, and both rollback journal and WAL
// mode, use the same historical migration chain shipped to existing users.
func fixture(t *testing.T, version int, journal string, populated bool) (string, *sql.DB) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "identity #é.db")
	db := openDB(t, path)
	var actual string
	require.NoError(t, db.QueryRow("PRAGMA journal_mode="+journal).Scan(&actual))
	for v := 1; v <= version; v++ {
		_, err := db.Exec(historicalSQL(t, v))
		require.NoError(t, err)
		_, err = db.Exec(fmt.Sprintf("PRAGMA user_version=%d", v))
		require.NoError(t, err)
	}
	if populated {
		_, err := db.Exec(`INSERT INTO users(id,username,password,totp_secret,totp_verified) VALUES('u','kept-user','kept-password','kept-totp',1)`)
		require.NoError(t, err)
		_, err = db.Exec(`INSERT INTO settings(key,value) VALUES('migration-fixture','kept-setting')`)
		require.NoError(t, err)
		_, err = db.Exec(`INSERT INTO tokens(id,user_id,access_token,refresh_token,access_token_type,refresh_token_expires_at,access_token_expires_at,scope,grant_type) VALUES('t','u','old-access-secret','old-refresh-secret','Bearer',datetime('now','+1 day'),datetime('now','+1 hour'),'openid','password')`)
		require.NoError(t, err)
		_, err = db.Exec(`INSERT INTO sessions(id,user_id,access_token,refresh_token) VALUES('s','u','old-access-secret','old-refresh-secret');
   INSERT INTO idp_sessions(id,user_id) VALUES('idp','u');
   INSERT INTO auth_codes(code,user_id,redirect_uri,expires_at) VALUES('auth','u','http://localhost/callback',datetime('now','+1 hour'));
   INSERT INTO mfa_challenges(id,user_id,method,login_state,expires_at) VALUES('mfa','u','totp','{}',datetime('now','+1 hour'));
   INSERT INTO passkey_challenges(id,user_id,challenge_data,type,expires_at) VALUES('passkey','u','{}','authentication',datetime('now','+1 hour'));
   INSERT INTO trusted_devices(id,user_id,expires_at) VALUES('trusted','u',datetime('now','+1 day'))`)
		require.NoError(t, err)
		if version >= 8 {
			_, err = db.Exec(`INSERT INTO device_codes(code,user_code,client_id,expires_at) VALUES('device','123456','client',datetime('now','+1 hour'))`)
			require.NoError(t, err)
		}
		if version >= 9 {
			_, err = db.Exec(`INSERT INTO magic_link_tokens(id,user_id,token_hash,code_hash,expires_at) VALUES('magic','u','old-magic','123456',datetime('now','+1 hour'))`)
			require.NoError(t, err)
		}
	}
	return path, db
}

func env(path string) []string {
	var values []string
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "AUTENTICO_") {
			values = append(values, value)
		}
	}
	return append(values,
		"AUTENTICO_DB_FILE_PATH="+path,
		"AUTENTICO_APP_URL=http://localhost:9999",
		"AUTENTICO_ACCESS_TOKEN_SECRET=migration-test-access-secret",
		"AUTENTICO_REFRESH_TOKEN_SECRET=migration-test-refresh-secret",
		"AUTENTICO_CSRF_SECRET_KEY=01234567890123456789012345678901")
}

func command(t *testing.T, path, input string, args ...string) (string, error) {
	t.Helper()
	return commandWithBinary(t, binary, path, input, args...)
}

func commandWithBinary(t *testing.T, executable, path, input string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Dir = filepath.Dir(path)
	cmd.Env = env(path)
	cmd.Stdin = strings.NewReader(input)
	output, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "CLI timed out: %s", output)
	return string(output), err
}
func migrate(t *testing.T, path string) (string, error) {
	t.Helper()
	return command(t, path, "", "migrate", "--approve-major=15")
}
func schema(t *testing.T, path string) int {
	t.Helper()
	var version int
	database := openDB(t, path)
	defer func() { _ = database.Close() }()
	require.NoError(t, database.QueryRow("PRAGMA user_version").Scan(&version))
	return version
}
func backups(t *testing.T, path string) []string {
	t.Helper()
	files, err := filepath.Glob(path + fmt.Sprintf(".pre-v%d-*.db", target))
	require.NoError(t, err)
	return files
}
func digest(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
func noRecovery(t *testing.T, path string) {
	t.Helper()
	_, err := os.Stat(path + ".migration.json")
	require.True(t, os.IsNotExist(err), "unexpected recovery state: %v", err)
}
func checkPurged(t *testing.T, path string) {
	t.Helper()
	db := openDB(t, path)
	for _, table := range []string{"tokens", "sessions", "idp_sessions", "auth_codes", "mfa_challenges", "passkey_challenges", "magic_link_tokens", "device_codes"} {
		var count int
		require.NoError(t, db.QueryRow("SELECT count(*) FROM "+table).Scan(&count))
		require.Zero(t, count, table)
	}
	var node, parent, unused int
	var plan string
	require.NoError(t, db.QueryRow(`EXPLAIN QUERY PLAN SELECT id FROM sessions WHERE refresh_token_hash = ?`, "lookup").Scan(&node, &parent, &unused, &plan))
	require.Contains(t, plan, "USING INDEX idx_sessions_refresh_token_hash")
	var username, password, totp, setting string
	var verified bool
	require.NoError(t, db.QueryRow(`SELECT username,password,totp_secret,totp_verified FROM users WHERE id='u'`).Scan(&username, &password, &totp, &verified))
	require.Equal(t, "kept-user", username)
	require.Equal(t, "kept-password", password)
	require.Equal(t, "kept-totp", totp)
	require.True(t, verified)
	require.NoError(t, db.QueryRow(`SELECT value FROM settings WHERE key='migration-fixture'`).Scan(&setting))
	require.Equal(t, "kept-setting", setting)
	var count int
	require.NoError(t, db.QueryRow("SELECT count(*) FROM trusted_devices").Scan(&count))
	require.Equal(t, 1, count)
	require.NoError(t, db.Close())
}

func TestUpgradeHistoricalDatabases(t *testing.T) {
	for _, version := range []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14} {
		for _, journal := range []string{"DELETE", "WAL"} {
			t.Run(fmt.Sprintf("v%d_%s", version, journal), func(t *testing.T) {
				path, db := fixture(t, version, journal, true)
				require.NoError(t, db.Close())
				output, err := migrate(t, path)
				require.NoError(t, err, output)
				require.Equal(t, target, schema(t, path))
				checkPurged(t, path)
				noRecovery(t, path)
				saved := backups(t, path)
				require.Len(t, saved, 1)
				require.Equal(t, version, schema(t, saved[0]))
				if runtime.GOOS != "windows" {
					info, err := os.Stat(saved[0])
					require.NoError(t, err)
					require.Equal(t, os.FileMode(0600), info.Mode().Perm())
				}
				before := digest(t, path)
				output, err = migrate(t, path)
				require.NoError(t, err, output)
				require.Contains(t, output, "Already up to date")
				require.Equal(t, before, digest(t, path))
				require.Len(t, backups(t, path), 1)
			})
		}
	}
}

func TestRoutineTotpReplayUpgradePreservesSessions(t *testing.T) {
	path, database := fixture(t, 15, "WAL", false)
	_, err := database.Exec(`INSERT INTO users(id,username,password,totp_secret,totp_verified)
		VALUES('routine-user','routine-user','kept-password','kept-seed',TRUE);
		INSERT INTO tokens(id,user_id,access_token_hash,refresh_token_hash,access_token_type,refresh_token_expires_at,access_token_expires_at,scope,grant_type)
		VALUES('routine-token','routine-user','kept-access-hash','kept-refresh-hash','Bearer',datetime('now','+1 day'),datetime('now','+1 hour'),'openid','password');
		INSERT INTO sessions(id,user_id,access_token_hash,refresh_token_hash) VALUES('routine-session','routine-user','kept-access-hash','kept-refresh-hash')`)
	require.NoError(t, err)
	require.NoError(t, database.Close())
	output, err := command(t, path, "", "migrate", "--approve-major=15")
	require.NoError(t, err, output)
	require.Equal(t, target, schema(t, path))
	require.Empty(t, backups(t, path))
	database = openDB(t, path)
	var step int64
	var secret, accessHash, sessionHash string
	require.NoError(t, database.QueryRow(`SELECT totp_last_used_step,totp_secret FROM users WHERE id='routine-user'`).Scan(&step, &secret))
	require.Equal(t, int64(-1), step)
	require.Equal(t, "kept-seed", secret)
	require.NoError(t, database.QueryRow(`SELECT access_token_hash FROM tokens WHERE id='routine-token'`).Scan(&accessHash))
	require.NoError(t, database.QueryRow(`SELECT access_token_hash FROM sessions WHERE id='routine-session'`).Scan(&sessionHash))
	require.Equal(t, "kept-access-hash", accessHash)
	require.Equal(t, accessHash, sessionHash)
}

func TestEmptyAndFreshInstallations(t *testing.T) {
	for _, version := range []int{0, 1, 14} {
		t.Run(strconv.Itoa(version), func(t *testing.T) {
			path, db := fixture(t, version, "WAL", false)
			require.NoError(t, db.Close())
			input := fmt.Sprintf("%d\n", target)
			args := []string{"migrate"}
			if version > 0 {
				input = ""
				args = append(args, "--approve-major=15")
			}
			output, err := command(t, path, input, args...)
			require.NoError(t, err, output)
			require.Equal(t, target, schema(t, path))
			noRecovery(t, path)
			if version == 0 {
				require.Empty(t, backups(t, path))
			} else {
				require.Len(t, backups(t, path), 1)
			}
		})
	}
}

func TestMajorApprovalAndStartupGate(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		args        []string
		message     string
	}{
		{"cancel", "no\n", []string{"migrate"}, "Migration cancelled"},
		{"numeric_confirmation", fmt.Sprintf("%d\n", target), []string{"migrate"}, "Everyone must sign in again"},
		{"EOF", "", []string{"migrate"}, "failed to read input"},
		{"wrong_version", "", []string{"migrate", "--approve-major=16"}, "not a known major"},
		{"release_instead_of_schema", "", []string{"migrate", "--approve-major=v3"}, "invalid value"},
		{"automatic_startup", "", []string{"start"}, "automatic upgrade is disabled"},
		{"manual_startup", "", []string{"start", "--no-auto-migrate"}, "run: autentico migrate"},
		{"onboarding", "", []string{"onboard", "--username=admin", "--password=password123"}, "automatic upgrade is disabled"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, db := fixture(t, 14, "WAL", true)
			require.NoError(t, db.Close())
			output, err := command(t, path, tc.input, tc.args...)
			require.Contains(t, output, tc.message)
			if tc.name == "numeric_confirmation" {
				require.NoError(t, err, output)
				checkPurged(t, path)
				return
			}
			if tc.name != "cancel" {
				require.Error(t, err, output)
			}
			require.Equal(t, 14, schema(t, path))
			require.Empty(t, backups(t, path))
			noRecovery(t, path)
			var raw string
			require.NoError(t, openDB(t, path).QueryRow("SELECT access_token FROM tokens WHERE id='t'").Scan(&raw))
			require.Equal(t, "old-access-secret", raw)
		})
	}
}

func TestFailureRestoresEntireUpgradeAndRetry(t *testing.T) {
	for _, version := range []int{1, 14} {
		for _, failure := range []string{"SQL", "delete", "commit"} {
			t.Run(fmt.Sprintf("v%d_%s", version, failure), func(t *testing.T) {
				path, db := fixture(t, version, "WAL", true)
				switch failure {
				case "SQL":
					_, err := db.Exec(`ALTER TABLE tokens ADD COLUMN client_id TEXT`)
					require.NoError(t, err)
				case "delete":
					_, err := db.Exec(`CREATE TRIGGER fail_migration BEFORE DELETE ON sessions BEGIN SELECT RAISE(ABORT,'injected deletion failure'); END`)
					require.NoError(t, err)
				case "commit":
					_, err := db.Exec(`CREATE TABLE parent(id INTEGER PRIMARY KEY); CREATE TABLE deferred_failure(id INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER fail_migration AFTER DELETE ON sessions BEGIN INSERT INTO deferred_failure VALUES(1); END`)
					require.NoError(t, err)
				}
				require.NoError(t, db.Close())
				require.NoError(t, os.Chmod(path, 0640))
				before := digest(t, path)
				output, err := migrate(t, path)
				require.Error(t, err, output)
				require.Contains(t, output, "restored schema")
				require.Equal(t, version, schema(t, path))
				require.Equal(t, before, digest(t, path))
				if runtime.GOOS != "windows" {
					info, statErr := os.Stat(path)
					require.NoError(t, statErr)
					require.Equal(t, os.FileMode(0640), info.Mode().Perm())
				}
				noRecovery(t, path)
				saved := backups(t, path)
				require.Len(t, saved, 1)
				require.Equal(t, before, digest(t, saved[0]))
				db = openDB(t, path)
				if failure == "SQL" {
					_, err = db.Exec(`ALTER TABLE tokens DROP COLUMN client_id`)
				} else {
					_, err = db.Exec(`DROP TRIGGER fail_migration`)
				}
				require.NoError(t, err)
				require.NoError(t, db.Close())
				output, err = migrate(t, path)
				require.NoError(t, err, output)
				require.Equal(t, target, schema(t, path))
				checkPurged(t, path)
			})
		}
	}
}

func TestCommittedWALIsInBackup(t *testing.T) {
	path, db := fixture(t, 14, "WAL", true)
	_, err := db.Exec("PRAGMA wal_autocheckpoint=0")
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO settings(key,value) VALUES('wal-only','committed in WAL')`)
	require.NoError(t, err)
	info, err := os.Stat(path + "-wal")
	require.NoError(t, err)
	require.Positive(t, info.Size())
	output, err := migrate(t, path)
	require.NoError(t, err, output)
	require.NoError(t, db.Close())
	saved := backups(t, path)
	require.Len(t, saved, 1)
	for _, file := range []string{path, saved[0]} {
		var value string
		require.NoError(t, openDB(t, file).QueryRow(`SELECT value FROM settings WHERE key='wal-only'`).Scan(&value))
		require.Equal(t, "committed in WAL", value)
	}
}

func TestPinnedReaderPreventsCheckpoint(t *testing.T) {
	path, db := fixture(t, 14, "WAL", true)
	reader := openDB(t, path)
	tx, err := reader.Begin()
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	var count int
	require.NoError(t, tx.QueryRow("SELECT count(*) FROM users").Scan(&count))
	_, err = db.Exec(`INSERT INTO settings(key,value) VALUES('new-write','must survive')`)
	require.NoError(t, err)
	output, err := migrate(t, path)
	require.Error(t, err, output)
	require.Contains(t, output, "checkpoint is busy")
	require.Empty(t, backups(t, path))
	noRecovery(t, path)
	require.Equal(t, 14, schema(t, path))
	require.NoError(t, tx.Rollback())
	require.NoError(t, reader.Close())
	require.NoError(t, db.Close())
	output, err = migrate(t, path)
	require.NoError(t, err, output)
	checkPurged(t, path)
}

type lockedBuffer struct {
	mu   sync.Mutex
	data bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data.Write(p)
}
func (b *lockedBuffer) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.data.String() }

// runUntil starts a real migrator and waits for an observable progress message.
// A slow SQLite trigger gives the parent a deterministic window to interrupt it
// or launch a competing process, without production fault-injection hooks.
func runUntil(t *testing.T, path, marker string) (*exec.Cmd, *lockedBuffer) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, binary, "migrate", "--approve-major=15")
	cmd.Dir = filepath.Dir(path)
	cmd.Env = env(path)
	pipe, err := cmd.StdoutPipe()
	require.NoError(t, err)
	var output lockedBuffer
	cmd.Stderr = &output
	require.NoError(t, cmd.Start())
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	reached := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(pipe)
		found := false
		for scanner.Scan() {
			line := scanner.Text()
			_, _ = output.Write([]byte(line + "\n"))
			if !found && strings.Contains(line, marker) {
				found = true
				reached <- true
			}
		}
		if !found {
			reached <- false
		}
	}()
	select {
	case found := <-reached:
		require.True(t, found, output.String())
	case <-ctx.Done():
		t.Fatal("did not reach migration progress: " + output.String())
	}
	return cmd, &output
}
func slowMigration(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.Exec(`CREATE TRIGGER slow_migration BEFORE DELETE ON tokens BEGIN
 SELECT sum(x) FROM (WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<5000000) SELECT x FROM n);
 END`)
	require.NoError(t, err)
}

func TestInterruptedUpgradeAndRecovery(t *testing.T) {
	path, db := fixture(t, 1, "WAL", true)
	slowMigration(t, db)
	require.NoError(t, db.Close())
	cmd, output := runUntil(t, path, "Applying migration v15")
	require.NoError(t, cmd.Process.Kill())
	require.Error(t, cmd.Wait(), output.String())
	_, err := os.Stat(path + ".migration.json")
	require.NoError(t, err)
	for _, args := range [][]string{{"start"}, {"start", "--no-auto-migrate"}} {
		text, err := command(t, path, "", args...)
		require.Error(t, err, text)
		require.Contains(t, text, "interrupted major migration")
	}
	// Recover without approving another attempt. All earlier committed schema
	// migrations must roll back to the v1 snapshot, including original tokens.
	text, err := command(t, path, "no\n", "migrate")
	require.NoError(t, err, text)
	require.Contains(t, text, "Restored pre-migration database")
	require.Equal(t, 1, schema(t, path))
	noRecovery(t, path)
	var raw string
	require.NoError(t, openDB(t, path).QueryRow("SELECT access_token FROM tokens WHERE id='t'").Scan(&raw))
	require.Equal(t, "old-access-secret", raw)
	db = openDB(t, path)
	_, err = db.Exec("DROP TRIGGER slow_migration")
	require.NoError(t, err)
	require.NoError(t, db.Close())
	text, err = migrate(t, path)
	require.NoError(t, err, text)
	checkPurged(t, path)
}

func TestConcurrentMigrators(t *testing.T) {
	path, db := fixture(t, 14, "WAL", true)
	slowMigration(t, db)
	require.NoError(t, db.Close())
	cmd, output := runUntil(t, path, "Major migration backup")
	text, err := migrate(t, path)
	require.Error(t, err, text)
	require.Contains(t, text, "database is in use")
	require.NoError(t, cmd.Wait(), output.String())
	require.Equal(t, target, schema(t, path))
	require.Len(t, backups(t, path), 1)
	noRecovery(t, path)
}

func TestDamagedRecoveryBackupFailsClosed(t *testing.T) {
	path, db := fixture(t, 14, "WAL", true)
	slowMigration(t, db)
	require.NoError(t, db.Close())
	cmd, output := runUntil(t, path, "Applying migration v15")
	require.NoError(t, cmd.Process.Kill())
	require.Error(t, cmd.Wait(), output.String())
	saved := backups(t, path)
	require.Len(t, saved, 1)
	file, err := os.OpenFile(saved[0], os.O_WRONLY, 0600)
	require.NoError(t, err)
	_, err = file.WriteAt([]byte("damaged"), 100)
	require.NoError(t, err)
	require.NoError(t, file.Close())
	text, err := migrate(t, path)
	require.Error(t, err, text)
	require.Contains(t, text, "checksum mismatch")
	_, err = os.Stat(path + ".migration.json")
	require.NoError(t, err)
	text, err = command(t, path, "", "start")
	require.Error(t, err, text)
	require.Contains(t, text, "interrupted major migration")
}

func TestInvalidDatabaseAndLockSetup(t *testing.T) {
	for _, kind := range []string{"future-schema", "corrupt-database", "blocked-lock"} {
		t.Run(kind, func(t *testing.T) {
			path, db := fixture(t, 14, "WAL", true)
			if kind == "future-schema" {
				_, err := db.Exec("PRAGMA user_version=999")
				require.NoError(t, err)
			}
			require.NoError(t, db.Close())
			if kind == "corrupt-database" {
				require.NoError(t, os.WriteFile(path, []byte("this is not SQLite"), 0600))
			}
			if kind == "blocked-lock" {
				require.NoError(t, os.Mkdir(path+".lock", 0700))
			}
			before := digest(t, path)
			text, err := migrate(t, path)
			require.Error(t, err, text)
			require.Equal(t, before, digest(t, path))
			require.Empty(t, backups(t, path))
			noRecovery(t, path)
		})
	}
}

func TestFreshContainerStartup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fresh.db")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	require.NoError(t, listener.Close())
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "start")
	cmd.Dir = filepath.Dir(path)
	cmd.Env = append(env(path), fmt.Sprintf("AUTENTICO_LISTEN_PORT=%d", port))
	var output lockedBuffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	require.NoError(t, cmd.Start())
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	client := &http.Client{Timeout: time.Second}
	endpoint := fmt.Sprintf("http://127.0.0.1:%d/.well-known/openid-configuration", port)
	for {
		resp, err := client.Get(endpoint)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				break
			}
		}
		select {
		case <-ctx.Done():
			t.Fatal(output.String())
		case <-time.After(20 * time.Millisecond):
		}
	}
	require.Equal(t, target, schema(t, path))
	require.Empty(t, backups(t, path))
	noRecovery(t, path)
	// The long-lived server's shared lock also prevents an offline migration
	// from replacing the database, even if an external tool changes its version.
	db := openDB(t, path)
	_, err = db.Exec("PRAGMA user_version=14")
	require.NoError(t, err)
	require.NoError(t, db.Close())
	text, err := migrate(t, path)
	require.Error(t, err, text)
	require.Contains(t, text, "database is in use")
}

func TestRecoveryRecordIsReadableAndPrivate(t *testing.T) {
	path, db := fixture(t, 14, "WAL", true)
	slowMigration(t, db)
	require.NoError(t, db.Close())
	cmd, output := runUntil(t, path, "Applying migration v15")
	require.NoError(t, cmd.Process.Kill())
	require.Error(t, cmd.Wait(), output.String())
	data, err := os.ReadFile(path + ".migration.json")
	require.NoError(t, err)
	var state struct {
		Backup, SHA256 string
		Version        int
	}
	require.NoError(t, json.Unmarshal(data, &state))
	require.Equal(t, 14, state.Version)
	require.Len(t, state.SHA256, 64)
	require.Equal(t, filepath.Base(state.Backup), state.Backup)
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path + ".migration.json")
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0600), info.Mode().Perm())
	}
}

func TestHeadlessMigrationOnNewVolume(t *testing.T) {
	path := filepath.Join(t.TempDir(), "new-volume.db")
	output, err := migrate(t, path)
	require.NoError(t, err, output)
	require.Equal(t, target, schema(t, path))
	require.Empty(t, backups(t, path))
	noRecovery(t, path)
}

func TestRecoveryRunsBeforeAlreadyUpToDateCheck(t *testing.T) {
	path, database := fixture(t, 14, "WAL", true)
	slowMigration(t, database)
	require.NoError(t, database.Close())
	cmd, output := runUntil(t, path, "Applying migration v15")
	require.NoError(t, cmd.Process.Kill())
	require.Error(t, cmd.Wait(), output.String())
	record, err := os.ReadFile(path + ".migration.json")
	require.NoError(t, err)
	text, err := migrate(t, path)
	require.NoError(t, err, text)
	require.Equal(t, target, schema(t, path))
	noRecovery(t, path)
	// Recreate a real, verified recovery record to model interruption after the
	// final commit but before record removal. The latest schema must not bypass recovery.
	require.NoError(t, os.WriteFile(path+".migration.json", record, 0600))
	text, err = command(t, path, "", "start")
	require.Error(t, err, text)
	require.Contains(t, text, "interrupted major migration")
	text, err = command(t, path, "no\n", "migrate")
	require.NoError(t, err, text)
	require.Contains(t, text, "Restored pre-migration database")
	require.NotContains(t, text, "Already up to date")
	require.Equal(t, 14, schema(t, path))
	noRecovery(t, path)
}

// Build a future CLI using Go's source overlay, leaving the working tree
// untouched. This exercises the actual approval flow across a later routine
// migration and proves a previous approval cannot approve a new major one.
func futureCLI(t *testing.T, major bool) string {
	t.Helper()
	sourcePath := filepath.Join(root, "pkg/db/migrations/migrations.go")
	data, err := os.ReadFile(sourcePath)
	require.NoError(t, err)
	source := strings.Replace(string(data), fmt.Sprintf("var SchemaVersion = %d", target), fmt.Sprintf("var SchemaVersion = %d", target+1), 1)
	anchor := fmt.Sprintf("{Version: %d, SQL: migration%03d},", target, target)
	require.Contains(t, source, anchor)
	source = strings.Replace(source, anchor, anchor+fmt.Sprintf("\n{Version: %d, Major: %t, SQL: `CREATE TABLE future_upgrade(id TEXT)`},", target+1, major), 1)
	dir := t.TempDir()
	replacement := filepath.Join(dir, "migrations.go")
	require.NoError(t, os.WriteFile(replacement, []byte(source), 0600))
	overlay, err := json.Marshal(map[string]map[string]string{"Replace": {sourcePath: replacement}})
	require.NoError(t, err)
	overlayPath := filepath.Join(dir, "overlay.json")
	require.NoError(t, os.WriteFile(overlayPath, overlay, 0600))
	executable := filepath.Join(dir, "autentico-future")
	if runtime.GOOS == "windows" {
		executable += ".exe"
	}
	cmd := exec.Command("go", "build", "-overlay", overlayPath, "-o", executable, ".")
	cmd.Dir = root
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, string(output))
	return executable
}

func TestHeadlessApprovalAcrossFutureMigrations(t *testing.T) {
	for _, major := range []bool{false, true} {
		t.Run(fmt.Sprintf("major_%t", major), func(t *testing.T) {
			executable := futureCLI(t, major)
			path, database := fixture(t, 14, "WAL", true)
			require.NoError(t, database.Close())
			output, err := migrate(t, path)
			require.NoError(t, err, output)
			if !major {
				// Explicit manual routine migrations keep numeric confirmation.
				output, err = commandWithBinary(t, executable, path, "no\n", "migrate")
				require.NoError(t, err, output)
				require.Contains(t, output, fmt.Sprintf("Type '%d'", target+1))
				require.Equal(t, target, schema(t, path))
			}
			output, err = commandWithBinary(t, executable, path, "", "migrate", "--approve-major=15")
			if major {
				require.Error(t, err, output)
				require.Contains(t, output, fmt.Sprintf("Major schema migrations: [%d]", target+1))
				require.Equal(t, target, schema(t, path))
				output, err = commandWithBinary(t, executable, path, "", "migrate", fmt.Sprintf("--approve-major=%d", target+1))
			}
			require.NoError(t, err, output)
			require.Equal(t, target+1, schema(t, path))
			require.NotContains(t, output, "Type '")
		})
	}
}
