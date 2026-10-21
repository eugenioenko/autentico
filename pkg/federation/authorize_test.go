package federation

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/user"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestCompleteAuthFlowRejectsInvalidRegistration(t *testing.T) {
	for _, tc := range []struct{ name, sql, clientID, redirect string }{
		{name: "unbound", redirect: "https://rp.example/callback"},
		{name: "unknown", clientID: "unknown", redirect: "https://rp.example/callback"},
		{name: "attacker redirect", clientID: "rp", redirect: "https://attacker.example/steal"},
		{name: "deactivated", clientID: "rp", redirect: "https://rp.example/callback", sql: "UPDATE clients SET is_active=FALSE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testutils.WithTestDB(t)
			testutils.InsertTestClient(t, "rp", []string{"https://rp.example/callback"})
			testutils.InsertTestUser(t, "victim")
			if tc.sql != "" {
				_, err := db.GetDB().Exec(tc.sql)
				require.NoError(t, err)
			}
			rr := httptest.NewRecorder()
			err := completeAuthFlow(rr, httptest.NewRequest(http.MethodGet, "/callback", nil), &user.User{ID: "victim"}, &FederationState{
				ClientID: tc.clientID, RedirectURI: tc.redirect, CodeChallenge: "challenge",
			})
			require.Error(t, err)
			require.Empty(t, rr.Header().Get("Location"))
			require.Empty(t, rr.Result().Cookies())
			for _, table := range []string{"auth_codes", "idp_sessions"} {
				var count int
				require.NoError(t, db.GetDB().QueryRow("SELECT count(*) FROM "+table).Scan(&count))
				require.Zero(t, count)
			}
		})
	}
}
