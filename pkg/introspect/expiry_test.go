package introspect

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/token"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestIntrospectionUsesPresentedTokenExpiry(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		accessTTL, refreshTTL  time.Duration
		presentRefresh, active bool
	}{
		{"access before expiry", time.Hour, 2 * time.Hour, false, true},
		{"refresh before either expiry", time.Hour, 2 * time.Hour, true, true},
		{"refresh outlives access", -time.Hour, time.Hour, true, true},
		{"access expired despite valid refresh", -time.Hour, time.Hour, false, false},
		{"refresh expired despite valid access", time.Hour, -time.Hour, true, false},
		{"access outlives refresh", time.Hour, -time.Hour, false, true},
		{"both expired", -time.Hour, -time.Minute, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testutils.WithTestDB(t)
			setupTestClient(t)
			testutils.InsertTestUser(t, "expiry-user")
			access, _, err := generateTestTokenAndStore("expiry-user")
			require.NoError(t, err)
			now := time.Now().UTC()
			accessExpiry, refreshExpiry := now.Add(tc.accessTTL), now.Add(tc.refreshTTL)
			_, err = db.GetDB().Exec("UPDATE tokens SET access_token_expires_at=?, refresh_token_expires_at=?", accessExpiry, refreshExpiry)
			require.NoError(t, err)
			presented, expectedExpiry := access, accessExpiry
			if tc.presentRefresh {
				presented, expectedExpiry = "refresh-token", refreshExpiry
			}
			form := url.Values{"token": {presented}}
			req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			withBasicAuth(req)
			rr := httptest.NewRecorder()
			HandleIntrospect(rr, req)
			require.Equal(t, http.StatusOK, rr.Code)
			var response IntrospectResponse
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &response))
			require.Equal(t, tc.active, response.Active)
			if tc.active {
				require.Equal(t, expectedExpiry.Unix(), response.Exp)
				require.Equal(t, "expiry-user", response.Sub)
			} else {
				require.JSONEq(t, `{"active":false}`, rr.Body.String())
			}
		})
	}
}

func TestIntrospectionRejectsAtReportedExpirationSecond(t *testing.T) {
	// Stored timestamps retain fractional seconds; signed JWT and introspection
	// exp are integers. Freeze now around each credential's reported expiry.
	stored := token.Token{AccessTokenHash: "access-hash", RefreshTokenHash: "refresh-hash",
		AccessTokenExpiresAt:  time.Unix(1900000000, 999999999),
		RefreshTokenExpiresAt: time.Unix(1900003600, 999999999)}
	for _, credential := range []struct {
		kind, hash string
		expiry     time.Time
	}{
		{"access", stored.AccessTokenHash, stored.AccessTokenExpiresAt},
		{"refresh", stored.RefreshTokenHash, stored.RefreshTokenExpiresAt},
	} {
		for _, boundary := range []struct {
			name    string
			offset  time.Duration
			expired bool
		}{
			{"immediately before", -time.Nanosecond, false},
			{"at reported exp", 0, true},
			{"immediately after", time.Nanosecond, true},
		} {
			t.Run(credential.kind+"/"+boundary.name, func(t *testing.T) {
				now := time.Unix(credential.expiry.Unix(), 0).Add(boundary.offset)
				require.Equal(t, boundary.expired, tokenExpired(&stored, credential.hash, now))
			})
		}
	}
}
