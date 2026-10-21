package security

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/session"
	"github.com/eugenioenko/autentico/pkg/token"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
	"github.com/stretchr/testify/require"
)

func refreshClientRequest(t *testing.T, ts *TestServer, refresh, clientID, secret string, basic bool) (*http.Response, []byte) {
	t.Helper()
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}}
	if !basic {
		if clientID != "" {
			form.Set("client_id", clientID)
		}
		if secret != "" {
			form.Set("client_secret", secret)
		}
	}
	r, err := http.NewRequest("POST", ts.BaseURL+"/oauth2/token", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basic {
		r.SetBasicAuth(clientID, secret)
	}
	resp, err := ts.Client.Do(r)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.NoError(t, err)
	return resp, body
}

// RFC 6749 §6 / §10.4: absent identity must not bypass client authentication,
// activation/grant policy, or replace a confidential client with an unowned token.
func TestRefreshClient_AuthenticationAndPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, clientID, secret, sql, errorCode string
		basic                                  bool
		status                                 int
	}{
		{name: "missing client", errorCode: "invalid_client", status: 401},
		{name: "secret without identity", secret: "sec-secret", errorCode: "invalid_client", status: 401},
		{name: "missing secret", clientID: "sec-confidential", errorCode: "invalid_client", status: 401},
		{name: "wrong secret", clientID: "sec-confidential", secret: "wrong", errorCode: "invalid_client", status: 401},
		{name: "another public client", clientID: "test-client", errorCode: "invalid_grant", status: 400},
		{name: "inactive client", clientID: "sec-confidential", secret: "sec-secret", sql: "UPDATE clients SET is_active=FALSE WHERE client_id='sec-confidential'", errorCode: "invalid_client", status: 401},
		{name: "refresh not allowed", clientID: "sec-confidential", secret: "sec-secret", sql: `UPDATE clients SET grant_types='["authorization_code","password"]' WHERE client_id='sec-confidential'`, errorCode: "unauthorized_client", status: 400},
		{name: "valid secret post", clientID: "sec-confidential", secret: "sec-secret", status: 200},
		{name: "valid basic auth", clientID: "sec-confidential", secret: "sec-secret", basic: true, status: 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := startTestServer(t)
			createTestUser(t, "refresh-client-user", "password123", "client@example.com")
			initial := obtainTokensViaConfidentialROPC(t, ts, "refresh-client-user", "password123")
			if tc.sql != "" {
				_, err := db.GetDB().Exec(tc.sql)
				require.NoError(t, err)
			}
			resp, body := refreshClientRequest(t, ts, initial.RefreshToken, tc.clientID, tc.secret, tc.basic)
			require.Equal(t, tc.status, resp.StatusCode, string(body))
			if tc.status != 200 {
				var rejected struct {
					Error string `json:"error"`
				}
				require.NoError(t, json.Unmarshal(body, &rejected))
				require.Equal(t, tc.errorCode, rejected.Error)
				var total, revoked int
				require.NoError(t, db.GetDB().QueryRow("SELECT COUNT(*),COUNT(revoked_at) FROM tokens").Scan(&total, &revoked))
				require.Equal(t, 1, total, "rejection must not mint tokens")
				require.Zero(t, revoked, "unauthenticated/unauthorized requests must not rotate or revoke the token")
				_, err := db.GetDB().Exec(`UPDATE clients SET is_active=TRUE,grant_types='["authorization_code","password","refresh_token"]' WHERE client_id='sec-confidential'`)
				require.NoError(t, err)
				resp, body = refreshClientRequest(t, ts, initial.RefreshToken, "sec-confidential", "sec-secret", true)
				require.Equal(t, 200, resp.StatusCode, "legitimate client can still redeem after rejection: %s", body)
			}
			var rotated token.TokenResponse
			require.NoError(t, json.Unmarshal(body, &rotated))
			claims, err := token.DecodeRefreshToken(rotated.RefreshToken, config.GetBootstrap().AuthRefreshTokenSecret)
			require.NoError(t, err)
			require.Equal(t, "sec-confidential", claims.ClientID)
			var boundClient string
			require.NoError(t, db.GetDB().QueryRow("SELECT client_id FROM tokens WHERE refresh_token_hash=?", utils.HashToken(rotated.RefreshToken)).Scan(&boundClient))
			require.Equal(t, "sec-confidential", boundClient)
		})
	}
}

func TestRefreshClient_PublicClientMustIdentifyItself(t *testing.T) {
	ts := startTestServer(t)
	createTestUser(t, "public-refresh-user", "password123", "public@example.com")
	initial := obtainTokensViaROPC(t, ts, "test-client", "public-refresh-user", "password123")
	resp, body := refreshClientRequest(t, ts, initial.RefreshToken, "", "", false)
	require.Equal(t, 401, resp.StatusCode, string(body))
	rotated := refreshTokens(t, ts, initial.RefreshToken, "test-client")
	claims, err := token.DecodeRefreshToken(rotated.RefreshToken, config.GetBootstrap().AuthRefreshTokenSecret)
	require.NoError(t, err)
	require.Equal(t, "test-client", claims.ClientID)
}

func TestRefreshClient_HistoricalUnboundTokenCannotAcquireClient(t *testing.T) {
	ts := startTestServer(t)
	usr := createTestUser(t, "unbound-refresh-user", "password123", "unbound@example.com")
	// Model a token minted by the previous missing-client bug; its hash/session
	// bindings are intact, but no registered client owns it.
	fullUser, err := user.UserByID(usr.ID)
	require.NoError(t, err)
	legacy, err := token.GenerateTokens(*fullUser, "", "openid", config.Get())
	require.NoError(t, err)
	require.NoError(t, token.CreateToken(token.Token{
		UserID: &usr.ID, ClientID: "", ACR: legacy.ACR, AccessToken: legacy.AccessToken, RefreshToken: legacy.RefreshToken,
		AccessTokenType: "Bearer", IssuedAt: time.Now(), Scope: "openid", GrantType: "refresh_token",
		AccessTokenExpiresAt: legacy.AccessExpiresAt, RefreshTokenExpiresAt: legacy.RefreshExpiresAt,
	}))
	require.NoError(t, session.CreateSession(session.Session{ID: legacy.SessionID, UserID: usr.ID, AccessToken: legacy.AccessToken, RefreshToken: legacy.RefreshToken, ExpiresAt: legacy.AccessExpiresAt}))
	resp, body := refreshClientRequest(t, ts, legacy.RefreshToken, "test-client", "", false)
	require.Equal(t, 400, resp.StatusCode, string(body))
	require.Contains(t, string(body), "invalid_grant")
	var n int
	require.NoError(t, db.GetDB().QueryRow("SELECT COUNT(*) FROM tokens").Scan(&n))
	require.Equal(t, 1, n)
}
