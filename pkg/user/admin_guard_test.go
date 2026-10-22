package user

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

var adminRemovalActions = []struct {
	name string
	run  func(string) error
}{
	{"demote", func(id string) error { return UpdateUser(id, UserUpdateRequest{Role: "user"}) }},
	{"deactivate", DeactivateUser},
	{"delete", HardDeleteUser},
}

func insertAdmin(t *testing.T, id string) {
	t.Helper()
	testutils.InsertTestUser(t, id)
	_, err := db.GetDB().Exec(`UPDATE users SET role='admin' WHERE id=?`, id)
	require.NoError(t, err)
}

func TestLastActiveAdminProtection(t *testing.T) {
	for _, action := range adminRemovalActions {
		t.Run(action.name, func(t *testing.T) {
			testutils.WithTestDB(t)
			insertAdmin(t, "last")
			insertAdmin(t, "inactive")
			_, err := db.GetDB().Exec(`UPDATE users SET deactivated_at=CURRENT_TIMESTAMP WHERE id='inactive'`)
			require.NoError(t, err)
			require.ErrorIs(t, action.run("last"), ErrLastActiveAdmin)
			usr, err := UserByID("last")
			require.NoError(t, err)
			require.Equal(t, "admin", usr.Role)
			// Profile updates and explicit admin role remain allowed for the last admin.
			require.NoError(t, UpdateUser("last", UserUpdateRequest{Nickname: "still-admin", Role: "admin"}))
			require.NoError(t, ReactivateUser("inactive"))
			require.NoError(t, action.run("last"))
			remaining, err := UserByID("inactive")
			require.NoError(t, err)
			require.Equal(t, "admin", remaining.Role)
		})
	}
}

func TestConcurrentAdminRemovals(t *testing.T) {
	for _, first := range adminRemovalActions {
		for _, second := range adminRemovalActions {
			t.Run(first.name+"/"+second.name, func(t *testing.T) {
				testutils.WithTotpKey(t)
				_, err := db.InitDB(filepath.Join(t.TempDir(), "admins.db"))
				require.NoError(t, err)
				t.Cleanup(db.CloseDB)
				// Exercise independent SQLite writers, beyond the normal single writer pool.
				db.GetWriteDB().SetMaxOpenConns(4)
				insertAdmin(t, "first")
				insertAdmin(t, "second")
				start := make(chan struct{})
				results := make(chan error, 2)
				var wg sync.WaitGroup
				for _, call := range []struct {
					id  string
					run func(string) error
				}{{"first", first.run}, {"second", second.run}} {
					wg.Add(1)
					go func(id string, run func(string) error) { defer wg.Done(); <-start; results <- run(id) }(call.id, call.run)
				}
				close(start)
				wg.Wait()
				close(results)
				succeeded, denied := 0, 0
				for err := range results {
					if err == nil {
						succeeded++
					} else {
						require.True(t, errors.Is(err, ErrLastActiveAdmin), "unexpected error: %v", err)
						denied++
					}
				}
				require.Equal(t, 1, succeeded)
				require.Equal(t, 1, denied)
				var remaining int
				require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM users WHERE role='admin' AND deactivated_at IS NULL`).Scan(&remaining))
				require.Equal(t, 1, remaining)
			})
		}
	}
}

func TestAdminMutationCommitFailureRollsBack(t *testing.T) {
	for _, action := range adminRemovalActions {
		t.Run(action.name, func(t *testing.T) {
			testutils.WithTestDB(t)
			insertAdmin(t, "target")
			insertAdmin(t, "other")
			_, err := db.GetDB().Exec(`INSERT INTO sessions(id,user_id) VALUES('session','target')`)
			require.NoError(t, err)
			_, err = db.GetDB().Exec(`CREATE TABLE reject_commit(user_id TEXT REFERENCES users(id) DEFERRABLE INITIALLY DEFERRED)`)
			require.NoError(t, err)
			event := "UPDATE OF role"
			condition := "NEW.role='user'"
			if action.name == "deactivate" {
				event = "UPDATE OF deactivated_at"
				condition = "NEW.deactivated_at IS NOT NULL"
			}
			if action.name == "delete" {
				event = "DELETE"
				condition = "OLD.id='target'"
			}
			_, err = db.GetDB().Exec(fmt.Sprintf(`CREATE TRIGGER reject_mutation AFTER %s ON users WHEN %s BEGIN INSERT INTO reject_commit VALUES('missing'); END`, event, condition))
			require.NoError(t, err)
			require.Error(t, action.run("target"))
			usr, err := UserByID("target")
			require.NoError(t, err)
			require.Equal(t, "admin", usr.Role)
			var sessions int
			require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM sessions WHERE user_id='target' AND deactivated_at IS NULL`).Scan(&sessions))
			require.Equal(t, 1, sessions)
			_, err = db.GetDB().Exec(`DROP TRIGGER reject_mutation`)
			require.NoError(t, err)
			require.NoError(t, action.run("target"), "connection remains usable after failed COMMIT")
		})
	}
}

func TestLastAdminDeletionPreservesThenRemovesAssociatedData(t *testing.T) {
	testutils.WithTestDB(t)
	insertAdmin(t, "target")
	for _, query := range []string{
		`INSERT INTO sessions(id,user_id) VALUES('session','target')`,
		`INSERT INTO password_reset_tokens(id,user_id,token_hash,expires_at) VALUES('reset','target','reset-hash',datetime('now','+1 hour'))`,
		`INSERT INTO magic_link_tokens(id,user_id,token_hash,expires_at) VALUES('magic','target','magic-hash',datetime('now','+1 hour'))`,
		`INSERT INTO device_codes(code,user_code,client_id,user_id,expires_at) VALUES('device','device-user','client','target',datetime('now','+1 hour'))`,
		`INSERT INTO user_consents(id,user_id,client_id,scopes) VALUES('consent','target','client','openid')`,
	} {
		_, err := db.GetDB().Exec(query)
		require.NoError(t, err)
	}
	require.ErrorIs(t, HardDeleteUser("target"), ErrLastActiveAdmin)
	for _, table := range []string{"sessions", "password_reset_tokens", "magic_link_tokens", "device_codes", "user_consents"} {
		var count int
		require.NoError(t, db.GetDB().QueryRow("SELECT COUNT(*) FROM "+table+" WHERE user_id='target'").Scan(&count))
		require.Equal(t, 1, count, table)
	}
	insertAdmin(t, "other")
	require.NoError(t, HardDeleteUser("target"))
	for _, table := range []string{"sessions", "password_reset_tokens", "magic_link_tokens", "device_codes", "user_consents"} {
		var count int
		require.NoError(t, db.GetDB().QueryRow("SELECT COUNT(*) FROM "+table+" WHERE user_id='target'").Scan(&count))
		require.Zero(t, count, table)
	}
}
