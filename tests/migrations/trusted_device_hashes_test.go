package migrationstest

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/totpsecret"
	"github.com/eugenioenko/autentico/pkg/utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

const legacyTrustCookie = "legacy-cookie-kept-through-upgrade"
const migrationVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
const migrationChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

func trustFixture(t *testing.T, journal string) (string, *sql.DB, string, time.Time, time.Time, time.Time) {
	t.Helper()
	path, database := fixture(t, 19, journal, false)
	sealed, err := totpsecret.Seal(totpKey, "kept", "JBSWY3DPEHPK3PXP")
	require.NoError(t, err)
	password, err := bcrypt.GenerateFromPassword([]byte("Password123!"), bcrypt.MinCost)
	require.NoError(t, err)
	_, err = database.Exec(`INSERT INTO users(id,username,password,totp_secret,totp_verified,two_factor_enabled,totp_last_used_step,totp_failed_attempts) VALUES('kept','kept',?,?,TRUE,TRUE,42,2);
 INSERT INTO users(id,username,password) VALUES('other','other','');
 INSERT INTO settings(key,value) VALUES('trust_device_enabled','true'),('mfa_method','totp');
 INSERT INTO clients(id,client_id,client_name,client_type,redirect_uris,post_logout_redirect_uris,grant_types,response_types,scopes,is_active) VALUES('account','autentico-account','Account','public','["http://localhost:3000/callback"]','[]','["authorization_code"]','["code"]','openid profile email',TRUE);
 INSERT INTO tokens(id,user_id,access_token_hash,refresh_token_hash,access_token_type,refresh_token_expires_at,access_token_expires_at,scope,grant_type) VALUES('kept-token','kept','access-hash','refresh-hash','Bearer',datetime('now','+1 day'),datetime('now','+1 hour'),'openid','password');
 INSERT INTO sessions(id,user_id,access_token_hash,refresh_token_hash) VALUES('kept-session','kept','access-hash','refresh-hash');
 INSERT INTO idp_sessions(id,user_id,mfa_method) VALUES('kept-browser','kept','totp')`, string(password), sealed)
	require.NoError(t, err)
	created := time.Now().UTC().Add(-24 * time.Hour).Truncate(time.Second)
	used := created.Add(time.Hour)
	expires := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second)
	for _, device := range []struct {
		token, user string
		expiry      time.Time
	}{{legacyTrustCookie, "kept", expires}, {"expired-cookie", "kept", time.Now().UTC().Add(-time.Minute)}, {"other-cookie", "other", expires}, {strings.Repeat("a", 64), "other", expires}} {
		_, err = database.Exec(`INSERT INTO trusted_devices(id,user_id,device_name,created_at,last_used_at,expires_at) VALUES(?,?,?, ?,?,?)`, device.token, device.user, "Legacy browser", created, used, device.expiry)
		require.NoError(t, err)
	}
	return path, database, sealed, created, used, expires
}

// trustedLogin uses a new browser for every attempt so SSO cannot hide a broken
// cookie migration or make a public ID appear to bypass MFA.
func trustedLogin(t *testing.T, base, cookie string) string {
	t.Helper()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	browser := &http.Client{Jar: jar, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer browser.CloseIdleConnections()
	form := url.Values{"response_type": {"code"}, "client_id": {"autentico-account"}, "redirect_uri": {"http://localhost:3000/callback"}, "scope": {"openid profile email"}, "state": {"migration-trust"}, "code_challenge": {migrationChallenge}, "code_challenge_method": {"S256"}}
	resp, err := browser.Get(base + "/oauth2/authorize?" + form.Encode())
	require.NoError(t, err)
	page, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	for _, name := range []string{"gorilla.csrf.Token", "authorize_sig"} {
		match := regexp.MustCompile(`name="` + regexp.QuoteMeta(name) + `" value="([^"]+)"`).FindSubmatch(page)
		require.Len(t, match, 2, "missing form field %s", name)
		form.Set(name, string(match[1]))
	}
	form.Set("username", "kept")
	form.Set("password", "Password123!")
	req, err := http.NewRequest(http.MethodPost, base+"/oauth2/login", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", base+"/oauth2/authorize")
	req.Header.Set("Origin", base)
	req.AddCookie(&http.Cookie{Name: "autentico_trusted_device", Value: cookie})
	resp, err = browser.Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusFound, resp.StatusCode)
	return resp.Header.Get("Location")
}

func TestTrustedDeviceMigrationPreservesCookiesAndRevocation(t *testing.T) {
	for _, journal := range []string{"DELETE", "WAL"} {
		for _, mode := range []string{"start", "interactive", "unattended"} {
			t.Run(journal+"/"+mode, func(t *testing.T) {
				path, database, sealed, created, used, expires := trustFixture(t, journal)
				require.NoError(t, database.Close())
				if mode != "start" {
					args := []string{"migrate"}
					input := fmt.Sprintf("%d\n", target)
					if mode == "unattended" {
						args = append(args, "--approve-major=15,17")
						input = ""
					}
					output, err := command(t, path, input, args...)
					require.NoError(t, err, output)
				}
				base, stop := startTotpServer(t, path)
				defer stop()
				require.Equal(t, target, schema(t, path))
				require.Empty(t, backups(t, path))
				noRecovery(t, path)
				database = openDB(t, path)
				var id, hash, userID, name string
				var actualCreated, actualUsed, actualExpiry time.Time
				require.NoError(t, database.QueryRow(`SELECT id,token_hash,user_id,device_name,created_at,last_used_at,expires_at FROM trusted_devices WHERE token_hash=?`, utils.HashToken(legacyTrustCookie)).Scan(&id, &hash, &userID, &name, &actualCreated, &actualUsed, &actualExpiry))
				require.NotEqual(t, legacyTrustCookie, id)
				require.NotEqual(t, hash, id)
				require.Equal(t, "kept", userID)
				require.Equal(t, "Legacy browser", name)
				require.True(t, created.Equal(actualCreated))
				require.True(t, used.Equal(actualUsed))
				require.True(t, expires.Equal(actualExpiry))
				var secret, access, refresh, method string
				var step int64
				var attempts, count int
				require.NoError(t, database.QueryRow(`SELECT totp_secret,totp_last_used_step,totp_failed_attempts FROM users WHERE id='kept'`).Scan(&secret, &step, &attempts))
				require.Equal(t, sealed, secret)
				require.EqualValues(t, 42, step)
				require.Equal(t, 2, attempts)
				for _, table := range []string{"tokens", "sessions"} {
					require.NoError(t, database.QueryRow(`SELECT access_token_hash,refresh_token_hash FROM `+table+` WHERE user_id='kept'`).Scan(&access, &refresh))
					require.Equal(t, "access-hash", access)
					require.Equal(t, "refresh-hash", refresh)
				}
				require.NoError(t, database.QueryRow(`SELECT mfa_method FROM idp_sessions WHERE id='kept-browser'`).Scan(&method))
				require.Equal(t, "totp", method)
				require.NoError(t, database.QueryRow(`SELECT count(*) FROM trusted_devices`).Scan(&count))
				require.Equal(t, 4, count)
				require.NoError(t, database.QueryRow(`SELECT count(*) FROM trusted_devices WHERE id IN (?,?,?,?) OR token_hash IS NULL`, legacyTrustCookie, "expired-cookie", "other-cookie", strings.Repeat("a", 64)).Scan(&count))
				require.Zero(t, count)
				var node, parent, unused int
				var plan string
				require.NoError(t, database.QueryRow(`EXPLAIN QUERY PLAN SELECT id FROM trusted_devices WHERE token_hash=?`, hash).Scan(&node, &parent, &unused, &plan))
				require.Contains(t, plan, "idx_trusted_devices_token_hash")
				require.NoError(t, database.Close())
				for _, value := range []string{id, hash, "expired-cookie", "other-cookie"} {
					require.Contains(t, trustedLogin(t, base, value), "/mfa?challenge_id=")
				}
				callback, err := url.Parse(trustedLogin(t, base, legacyTrustCookie))
				require.NoError(t, err)
				code := callback.Query().Get("code")
				require.NotEmpty(t, code)
				resp, err := http.PostForm(base+"/oauth2/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {"autentico-account"}, "redirect_uri": {"http://localhost:3000/callback"}, "code": {code}, "code_verifier": {migrationVerifier}})
				require.NoError(t, err)
				var tokens struct {
					AccessToken string `json:"access_token"`
				}
				require.NoError(t, json.NewDecoder(resp.Body).Decode(&tokens))
				require.NoError(t, resp.Body.Close())
				require.Equal(t, http.StatusOK, resp.StatusCode)
				require.NotEmpty(t, tokens.AccessToken)
				req, err := http.NewRequest(http.MethodGet, base+"/account/api/trusted-devices", nil)
				require.NoError(t, err)
				req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
				resp, err = http.DefaultClient.Do(req)
				require.NoError(t, err)
				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				require.NoError(t, resp.Body.Close())
				require.Equal(t, http.StatusOK, resp.StatusCode)
				require.Contains(t, string(body), id)
				require.NotContains(t, string(body), legacyTrustCookie)
				require.NotContains(t, string(body), hash)
				req, err = http.NewRequest(http.MethodDelete, base+"/account/api/trusted-devices/"+id, nil)
				require.NoError(t, err)
				req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
				resp, err = http.DefaultClient.Do(req)
				require.NoError(t, err)
				require.NoError(t, resp.Body.Close())
				require.Equal(t, http.StatusOK, resp.StatusCode)
				require.Contains(t, trustedLogin(t, base, legacyTrustCookie), "/mfa?challenge_id=")
			})
		}
	}
}

func TestTrustedDeviceMigrationFailureRollsBackAndRetries(t *testing.T) {
	for _, journal := range []string{"DELETE", "WAL"} {
		for _, mode := range []string{"migrate", "start"} {
			for _, failure := range []string{"index", "update", "commit"} {
				t.Run(journal+"/"+mode+"/"+failure, func(t *testing.T) {
					path, database, _, _, _, _ := trustFixture(t, journal)
					var err error
					cleanup := "DROP TRIGGER fail_trust"
					switch failure {
					case "index":
						_, err = database.Exec(`CREATE TABLE collision(id TEXT);CREATE INDEX idx_trusted_devices_token_hash ON collision(id)`)
						cleanup = "DROP INDEX idx_trusted_devices_token_hash"
					case "update":
						_, err = database.Exec(`CREATE TRIGGER fail_trust BEFORE UPDATE ON trusted_devices WHEN OLD.id='other-cookie' BEGIN SELECT RAISE(ABORT,'injected trust failure');END`)
					case "commit":
						_, err = database.Exec(`CREATE TABLE parent(id INTEGER PRIMARY KEY);CREATE TABLE deferred_failure(id INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED);
      CREATE TRIGGER fail_trust AFTER UPDATE ON trusted_devices WHEN OLD.id='other-cookie' BEGIN INSERT INTO deferred_failure VALUES(1);END`)
					}
					require.NoError(t, err)
					require.NoError(t, database.Close())
					output, err := command(t, path, fmt.Sprintf("%d\n", target), mode)
					require.Error(t, err, output)
					require.Equal(t, 19, schema(t, path))
					require.Empty(t, backups(t, path))
					noRecovery(t, path)
					database = openDB(t, path)
					var count int
					require.NoError(t, database.QueryRow(`SELECT count(*) FROM trusted_devices WHERE id=?`, legacyTrustCookie).Scan(&count))
					require.Equal(t, 1, count)
					require.NoError(t, database.QueryRow(`SELECT count(*) FROM pragma_table_info('trusted_devices') WHERE name='token_hash'`).Scan(&count))
					require.Zero(t, count, "partial DDL must roll back")
					_, err = database.Exec(cleanup)
					require.NoError(t, err)
					require.NoError(t, database.Close())
					output, err = command(t, path, fmt.Sprintf("%d\n", target), "migrate")
					require.NoError(t, err, output)
					require.Equal(t, target, schema(t, path))
					database = openDB(t, path)
					require.NoError(t, database.QueryRow(`SELECT count(*) FROM trusted_devices WHERE token_hash=?`, utils.HashToken(legacyTrustCookie)).Scan(&count))
					require.Equal(t, 1, count)
				})
			}
		}
	}
}
