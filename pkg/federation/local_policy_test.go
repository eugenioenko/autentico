package federation

import (
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/user"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestFederationCompletionEnforcesLocalMfaAndConsent(t *testing.T) {
	for _, requireMfa := range []bool{true, false} {
		t.Run(map[bool]string{true: "MFA first", false: "consent first"}[requireMfa], func(t *testing.T) {
			testutils.WithTestDB(t)
			testutils.WithConfigOverride(t, func() {
				config.Values.RequireMfa = requireMfa
				config.Values.MfaMethod = "totp"
				config.Values.TrustDeviceEnabled = false
			})
			testutils.InsertTestClient(t, "c1", []string{"http://localhost/cb"})
			_, err := db.GetDB().Exec(`UPDATE clients SET consent_required=TRUE WHERE client_id='c1'`)
			require.NoError(t, err)
			created, err := user.CreateUser("local", "Password123!", "local@example.com")
			require.NoError(t, err)
			usr, err := user.UserByID(created.ID)
			require.NoError(t, err)
			rr := httptest.NewRecorder()
			err = completeAuthFlow(rr, httptest.NewRequest("GET", "/callback", nil), usr, &FederationState{ClientID: "c1", RedirectURI: "http://localhost/cb", Scope: "openid", CodeChallenge: "challenge", CodeChallengeMethod: "S256"})
			require.NoError(t, err)
			target, err := url.Parse(rr.Header().Get("Location"))
			require.NoError(t, err)
			require.Equal(t, map[bool]string{true: "/oauth2/mfa", false: "/oauth2/consent"}[requireMfa], target.Path)
			var count int
			require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM auth_codes`).Scan(&count))
			require.Zero(t, count)
			if requireMfa {
				require.Empty(t, rr.Result().Cookies())
			}
		})
	}
}
