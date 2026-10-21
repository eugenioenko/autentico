package token

import (
	"fmt"
	"testing"
	"time"

	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/devicecode"
	"github.com/eugenioenko/autentico/pkg/session"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

const deviceGrant = "urn:ietf:params:oauth:grant-type:device_code"

type issuanceFixture struct {
	request TokenRequest
	token   Token
	session session.Session
	initial int
}

func issuanceRows(t *testing.T, grant string) (Token, session.Session) {
	t.Helper()
	usr, err := user.UserByID("atomic-user")
	require.NoError(t, err)
	issued, err := GenerateTokens(*usr, "atomic-client", "openid", config.Get())
	require.NoError(t, err)
	return Token{UserID: &usr.ID, ClientID: "atomic-client", ACR: issued.ACR, AccessToken: issued.AccessToken, RefreshToken: issued.RefreshToken,
			AccessTokenType: "Bearer", AccessTokenExpiresAt: issued.AccessExpiresAt, RefreshTokenExpiresAt: issued.RefreshExpiresAt, IssuedAt: time.Now().UTC(), Scope: "openid", GrantType: grant},
		session.Session{ID: issued.SessionID, UserID: usr.ID, AccessToken: issued.AccessToken, RefreshToken: issued.RefreshToken, ExpiresAt: issued.AccessExpiresAt}
}

func setupIssuance(t *testing.T, grant string) issuanceFixture {
	t.Helper()
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "atomic-user")
	testutils.InsertTestClient(t, "atomic-client", []string{"http://localhost/callback"})
	fixture := issuanceFixture{request: TokenRequest{GrantType: grant, ClientID: "atomic-client", RedirectURI: "http://localhost/callback"}}
	switch grant {
	case "authorization_code":
		fixture.request.Code = "atomic-code"
		require.NoError(t, authcode.CreateAuthCode(authcode.AuthCode{Code: fixture.request.Code, UserID: "atomic-user", ClientID: "atomic-client", RedirectURI: fixture.request.RedirectURI, ExpiresAt: time.Now().Add(time.Hour)}))
	case "refresh_token":
		old, oldSession := issuanceRows(t, "password")
		require.NoError(t, CreateToken(old))
		require.NoError(t, session.CreateSession(oldSession))
		fixture.request.RefreshToken = old.RefreshToken
		fixture.initial = 1
	case deviceGrant:
		fixture.request.DeviceCode = "atomic-device"
		require.NoError(t, devicecode.CreateDeviceCode(devicecode.DeviceCode{Code: "atomic-device", UserCode: "ATOMIC-DEVICE", ClientID: "atomic-client", Status: "pending", ExpiresAt: time.Now().Add(time.Hour)}))
		require.NoError(t, devicecode.AuthorizeDeviceCode("ATOMIC-DEVICE", "atomic-user"))
	}
	fixture.token, fixture.session = issuanceRows(t, grant)
	return fixture
}

func assertIssuancePending(t *testing.T, fixture issuanceFixture) {
	t.Helper()
	switch fixture.request.GrantType {
	case "authorization_code":
		code, err := authcode.AuthCodeByCodeIncludingUsed(fixture.request.Code)
		require.NoError(t, err)
		require.False(t, code.Used)
	case "refresh_token":
		var revoked *time.Time
		require.NoError(t, db.GetDB().QueryRow("SELECT revoked_at FROM tokens WHERE refresh_token_hash=?", utils.HashToken(fixture.request.RefreshToken)).Scan(&revoked))
		require.Nil(t, revoked)
	case deviceGrant:
		code, err := devicecode.DeviceCodeByCode(fixture.request.DeviceCode)
		require.NoError(t, err)
		require.Equal(t, "authorized", code.Status)
	}
	for _, table := range []string{"tokens", "sessions"} {
		var n int
		require.NoError(t, db.GetDB().QueryRow("SELECT COUNT(*) FROM "+table).Scan(&n))
		require.Equal(t, fixture.initial, n, table)
	}
}

func TestGrantIssuance_RollsBackAndCanRetry(t *testing.T) {
	for _, grant := range []string{"authorization_code", "refresh_token", deviceGrant} {
		for _, failure := range []string{"token insert", "session insert", "commit"} {
			t.Run(grant+"/"+failure, func(t *testing.T) {
				fixture := setupIssuance(t, grant)
				if failure == "commit" {
					// A deferred FK failure exercises SQLite's failed-COMMIT state.
					_, err := db.GetDB().Exec("PRAGMA defer_foreign_keys=ON")
					require.NoError(t, err)
					fixture.session.UserID = "missing-at-commit"
				} else {
					table := "tokens"
					if failure == "session insert" {
						table = "sessions"
					}
					_, err := db.GetDB().Exec(fmt.Sprintf(`CREATE TRIGGER reject_issuance BEFORE INSERT ON %s BEGIN SELECT RAISE(ABORT,'issuance failure'); END`, table))
					require.NoError(t, err)
				}
				err := storeGrantTokens(fixture.request, fixture.token, fixture.session)
				require.Error(t, err)
				assertIssuancePending(t, fixture)
				if failure != "commit" {
					_, err = db.GetDB().Exec("DROP TRIGGER reject_issuance")
					require.NoError(t, err)
				}
				fixture.session.UserID = "atomic-user"
				// Also proves the writer is usable after a failed SQLite COMMIT.
				require.NoError(t, storeGrantTokens(fixture.request, fixture.token, fixture.session))
				for _, table := range []string{"tokens", "sessions"} {
					var n int
					require.NoError(t, db.GetDB().QueryRow("SELECT COUNT(*) FROM "+table).Scan(&n))
					require.Equal(t, fixture.initial+1, n, table)
				}
			})
		}
	}
}

func TestGrantIssuance_ConcurrentSingleWinner(t *testing.T) {
	for _, grant := range []string{"authorization_code", "refresh_token", deviceGrant} {
		t.Run(grant, func(t *testing.T) {
			fixture := setupIssuance(t, grant)
			type candidate struct {
				token   Token
				session session.Session
			}
			candidates := make([]candidate, 20)
			for i := range candidates {
				candidates[i].token, candidates[i].session = issuanceRows(t, grant)
			}
			start := make(chan struct{})
			results := make(chan error, len(candidates))
			for _, candidate := range candidates {
				go func() { <-start; results <- storeGrantTokens(fixture.request, candidate.token, candidate.session) }()
			}
			close(start)
			wins := 0
			for range candidates {
				err := <-results
				if err == nil {
					wins++
				} else {
					require.ErrorIs(t, err, errGrantConsumed)
				}
			}
			require.Equal(t, 1, wins)
			for _, table := range []string{"tokens", "sessions"} {
				var n int
				require.NoError(t, db.GetDB().QueryRow("SELECT COUNT(*) FROM "+table).Scan(&n))
				require.Equal(t, fixture.initial+1, n, table)
			}
		})
	}
}

func TestGrantIssuance_RechecksExpiryWithoutConsuming(t *testing.T) {
	for _, grant := range []string{"authorization_code", "refresh_token", deviceGrant} {
		t.Run(grant, func(t *testing.T) {
			fixture := setupIssuance(t, grant)
			query, value := "UPDATE auth_codes SET expires_at=? WHERE code=?", fixture.request.Code
			if grant == "refresh_token" {
				query, value = "UPDATE tokens SET refresh_token_expires_at=? WHERE refresh_token_hash=?", utils.HashToken(fixture.request.RefreshToken)
			}
			if grant == deviceGrant {
				query, value = "UPDATE device_codes SET expires_at=? WHERE code=?", fixture.request.DeviceCode
			}
			_, err := db.GetDB().Exec(query, time.Now().Add(-time.Hour), value)
			require.NoError(t, err)
			require.ErrorIs(t, storeGrantTokens(fixture.request, fixture.token, fixture.session), errGrantExpired)
			assertIssuancePending(t, fixture)
		})
	}
}
