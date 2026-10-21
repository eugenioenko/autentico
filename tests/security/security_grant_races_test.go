package security

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/devicecode"
	"github.com/eugenioenko/autentico/pkg/token"
	"github.com/eugenioenko/autentico/pkg/utils"
	"github.com/stretchr/testify/require"
)

// TestGrantRedemptionRace exercises the HTTP boundary, including requests that
// read the credential before another request commits its consumption.
func TestGrantRedemptionRace(t *testing.T) {
	for _, grant := range []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"} {
		t.Run(grant, func(t *testing.T) {
			ts := startTestServer(t)
			usr := createTestUser(t, "race-user", "Password123!", "race@example.com")
			form := url.Values{"grant_type": {grant}, "client_id": {"test-client"}}
			switch grant {
			case "authorization_code":
				form.Set("code", performAuthCodeFlow(t, ts, "test-client", "http://localhost:3000/callback", usr.Username, "Password123!", "race"))
				form.Set("redirect_uri", "http://localhost:3000/callback")
				form.Set("code_verifier", testCodeVerifier)
			case "refresh_token":
				form.Set("refresh_token", obtainTokensViaROPC(t, ts, "test-client", usr.Username, "Password123!").RefreshToken)
			default:
				_, err := db.GetDB().Exec(`UPDATE clients SET grant_types = ? WHERE client_id = 'test-client'`, `["password","refresh_token","urn:ietf:params:oauth:grant-type:device_code"]`)
				require.NoError(t, err)
				resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/device_authorization", url.Values{"client_id": {"test-client"}, "scope": {"openid profile"}})
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, resp.StatusCode)
				var issued devicecode.DeviceAuthorizationResponse
				require.NoError(t, json.NewDecoder(resp.Body).Decode(&issued))
				require.NoError(t, resp.Body.Close())
				require.NoError(t, devicecode.AuthorizeDeviceCode(devicecode.NormalizeUserCode(issued.UserCode), usr.ID))
				form.Set("device_code", issued.DeviceCode)
			}
			var beforeTokens, beforeSessions int
			require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM tokens`).Scan(&beforeTokens))
			require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&beforeSessions))
			type result struct {
				status int
				body   []byte
				err    error
			}
			const requests = 20
			start, results := make(chan struct{}), make(chan result, requests)
			for range requests {
				go func() {
					<-start
					resp, err := http.PostForm(ts.BaseURL+"/oauth2/token", form)
					if err != nil {
						results <- result{err: err}
						return
					}
					body, readErr := io.ReadAll(resp.Body)
					_ = resp.Body.Close()
					results <- result{status: resp.StatusCode, body: body, err: readErr}
				}()
			}
			close(start)
			winners := 0
			for range requests {
				r := <-results
				require.NoError(t, r.err)
				if r.status == http.StatusOK {
					winners++
					var issued token.TokenResponse
					require.NoError(t, json.Unmarshal(r.body, &issued))
					require.NotEmpty(t, issued.AccessToken)
					require.NotEmpty(t, issued.RefreshToken)
				} else {
					require.Equal(t, http.StatusBadRequest, r.status, "%s", r.body)
					var rejected struct {
						Error string `json:"error"`
					}
					require.NoError(t, json.Unmarshal(r.body, &rejected))
					// Device polling can be throttled before reaching the single-use guard.
					allowed := []string{"invalid_grant"}
					if grant == "urn:ietf:params:oauth:grant-type:device_code" {
						allowed = append(allowed, "slow_down")
					}
					require.Contains(t, allowed, rejected.Error)
				}
			}
			require.Equal(t, 1, winners, "one credential must produce exactly one token pair")
			var afterTokens, afterSessions int
			require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM tokens`).Scan(&afterTokens))
			require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&afterSessions))
			require.Equal(t, beforeTokens+1, afterTokens)
			require.Equal(t, beforeSessions+1, afterSessions)
		})
	}
}

func TestAuthorizationReplayRevokesRotatedDescendants(t *testing.T) {
	ts := startTestServer(t)
	usr := createTestUser(t, "lineage-user", "Password123!", "lineage@example.com")
	code := performAuthCodeFlow(t, ts, "test-client", "http://localhost:3000/callback", usr.Username, "Password123!", "lineage")
	initial := exchangeCode(t, ts, code, "http://localhost:3000/callback", "test-client", testCodeVerifier)
	rotated := refreshTokens(t, ts, initial.RefreshToken, "test-client")
	latest := refreshTokens(t, ts, rotated.RefreshToken, "test-client")
	independent := obtainTokensViaROPC(t, ts, "test-client", usr.Username, "Password123!")
	independentRotated := refreshTokens(t, ts, independent.RefreshToken, "test-client")
	otherClient := obtainTokensViaROPC(t, ts, "other-client", usr.Username, "Password123!")
	// An invalid proof must not let a caller revoke an already issued grant.
	exchangeCodeExpectError(t, ts, code, "http://localhost:3000/callback", "test-client", "wrong", http.StatusBadRequest, "invalid_grant")
	var live int
	require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM tokens WHERE access_token_hash = ? AND revoked_at IS NULL`, utils.HashToken(latest.AccessToken)).Scan(&live))
	require.Equal(t, 1, live)
	exchangeCodeExpectError(t, ts, code, "http://localhost:3000/callback", "test-client", testCodeVerifier, http.StatusBadRequest, "invalid_grant")
	for _, pair := range []*token.TokenResponse{initial, rotated, latest} {
		require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM tokens WHERE access_token_hash = ? AND revoked_at IS NULL`, utils.HashToken(pair.AccessToken)).Scan(&live))
		require.Zero(t, live, "replay must revoke descendants after multiple rotations")
	}
	for i, pair := range []*token.TokenResponse{independentRotated, otherClient} {
		require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM tokens WHERE access_token_hash = ? AND revoked_at IS NULL`, utils.HashToken(pair.AccessToken)).Scan(&live))
		require.Equal(t, 1, live, fmt.Sprintf("independent grant %d must survive", i))
	}
}

func TestRefreshInvalidScopeDoesNotConsumeCredential(t *testing.T) {
	ts := startTestServer(t)
	usr := createTestUser(t, "scope-user", "Password123!", "scope@example.com")
	original := obtainTokensViaROPC(t, ts, "test-client", usr.Username, "Password123!")
	_, status := refreshTokensWithScope(t, ts, original.RefreshToken, "test-client", "not-granted", http.StatusBadRequest)
	require.Equal(t, http.StatusBadRequest, status)
	rotated := refreshTokens(t, ts, original.RefreshToken, "test-client")
	require.NotEqual(t, original.RefreshToken, rotated.RefreshToken)
}
