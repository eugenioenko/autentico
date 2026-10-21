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
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "expiry-boundary")
	access, _, err := generateTestTokenAndStore("expiry-boundary")
	require.NoError(t, err)
	// SQLite retains fractional seconds, but RFC 7662 §2.2 exp and JWT exp
	// report an integer. The credential must already be inactive at that second.
	expiresAt := time.Unix(time.Now().Unix(), 999999999)
	_, err = db.GetDB().Exec("UPDATE tokens SET access_token_expires_at=?", expiresAt)
	require.NoError(t, err)
	_, err = IntrospectToken(access)
	require.Error(t, err)
}
