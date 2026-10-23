package migrationstest

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/utils"
	"github.com/stretchr/testify/require"
)

func TestBrowserMfaRoutineUpgradePreservesLegacySessions(t *testing.T) {
	for _, journal := range []string{"DELETE", "WAL"} {
		for _, mode := range []string{"migrate", "start"} {
			t.Run(journal+"/"+mode, func(t *testing.T) {
				path, database := fixture(t, 17, journal, false)
				_, err := database.Exec(`INSERT INTO users(id,username,password) VALUES('kept','kept','');
INSERT INTO idp_sessions(id,user_id,user_agent,ip_address) VALUES('legacy','kept','kept browser','192.0.2.1');
INSERT INTO trusted_devices(id,user_id,expires_at) VALUES('device','kept',datetime('now','+1 day'))`)
				require.NoError(t, err)
				require.NoError(t, database.Close())
				if mode == "migrate" {
					output, err := command(t, path, fmt.Sprintf("%d\n", target), "migrate")
					require.NoError(t, err, output)
					require.NotContains(t, output, "Everyone must sign in again")
				} else {
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
					cmd.Stdout, cmd.Stderr = &output, &output
					require.NoError(t, cmd.Start())
					defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
					client := &http.Client{Timeout: time.Second}
					endpoint := fmt.Sprintf("http://127.0.0.1:%d/.well-known/openid-configuration", port)
					for {
						resp, err := client.Get(endpoint)
						if err == nil {
							_, _ = io.Copy(io.Discard, resp.Body)
							_ = resp.Body.Close()
							if resp.StatusCode == http.StatusOK {
								break
							}
						}
						select {
						case <-ctx.Done():
							t.Fatal(output.String())
						case <-time.After(20 * time.Millisecond):
						}
					}
				}
				require.Equal(t, target, schema(t, path))
				database = openDB(t, path)
				var userID, method, agent, ip string
				require.NoError(t, database.QueryRow(`SELECT user_id,mfa_method,user_agent,ip_address FROM idp_sessions WHERE id='legacy'`).Scan(&userID, &method, &agent, &ip))
				require.Equal(t, "kept", userID)
				require.Empty(t, method, "legacy sessions cannot assert completed MFA")
				require.Equal(t, "kept browser", agent)
				require.Equal(t, "192.0.2.1", ip)
				var count int
				require.NoError(t, database.QueryRow(`SELECT COUNT(*) FROM trusted_devices WHERE token_hash=?`, utils.HashToken("device")).Scan(&count))
				require.Equal(t, 1, count)
				require.Empty(t, backups(t, path))
				noRecovery(t, path)
			})
		}
	}
}
