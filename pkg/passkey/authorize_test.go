package passkey

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/user"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestPasskeyRejectsStaleAuthorizationBeforeSideEffects(t *testing.T) {
	for _, tc := range []struct{ name, sql, redirect string }{
		{name: "unregistered redirect", redirect: "https://attacker.example/steal"},
		{name: "client disabled", sql: "UPDATE clients SET is_active=FALSE WHERE client_id='c1'", redirect: "http://localhost/cb"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withPasskeyTestDB(t)
			withPasskeyConfig(t)
			testutils.InsertTestUser(t, "victim")
			state, err := json.Marshal(LoginState{ClientID: "c1", RedirectURI: tc.redirect, Scope: "openid", CodeChallenge: "challenge", CodeChallengeMethod: "S256"})
			require.NoError(t, err)
			if tc.sql != "" {
				_, err := db.GetDB().Exec(tc.sql)
				require.NoError(t, err)
			}
			for _, flow := range []struct {
				name, kind string
				handler    http.HandlerFunc
			}{
				{"registration", "registration", HandleRegisterFinish},
				{"login", "authentication", HandleLoginFinish},
				{"discoverable", "discoverable-authentication", HandleDiscoverableLoginFinish},
			} {
				require.NoError(t, CreatePasskeyChallenge(PasskeyChallenge{ID: flow.name, UserID: "victim",
					ChallengeData: sampleChallengeData(), Type: flow.kind, LoginState: string(state), ExpiresAt: time.Now().Add(time.Minute)}))
				rr := httptest.NewRecorder()
				flow.handler(rr, httptest.NewRequest(http.MethodPost, "/finish?challenge_id="+flow.name, strings.NewReader(`{}`)))
				require.Equal(t, http.StatusBadRequest, rr.Code, flow.name)
				require.Contains(t, rr.Body.String(), map[bool]string{true: "unknown or inactive client", false: "redirect_uri"}[tc.sql != ""])
				challenge, err := PasskeyChallengeByIDIncludingExpired(flow.name)
				require.NoError(t, err)
				require.False(t, challenge.Used)
			}
			rr := httptest.NewRecorder()
			_, err = completeAuthFlow(rr, httptest.NewRequest(http.MethodPost, "/finish", nil), &user.User{ID: "victim"}, string(state))
			require.Error(t, err)
			require.Empty(t, rr.Result().Cookies())
			for _, table := range []string{"auth_codes", "idp_sessions", "passkey_credentials"} {
				var count int
				require.NoError(t, db.GetDB().QueryRow("SELECT count(*) FROM "+table).Scan(&count))
				require.Zero(t, count, table)
			}
			var count int
			require.NoError(t, db.GetDB().QueryRow("SELECT count(*) FROM users WHERE id='victim'").Scan(&count))
			require.Equal(t, 1, count)
		})
	}
}
