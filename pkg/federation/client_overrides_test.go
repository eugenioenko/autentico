package federation

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/user"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestFederationUsesCurrentClientCodeLifetime(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "c1", []string{"http://localhost/cb"})
	testutils.WithConfigOverride(t, func() { config.Values.AuthAuthorizationCodeExpiration = 10 * time.Minute })
	created, err := user.CreateUser("lifetime-user", "Password123!", "lifetime@example.com")
	require.NoError(t, err)
	usr, err := user.UserByID(created.ID)
	require.NoError(t, err)
	_, err = db.GetDB().Exec(`UPDATE clients SET authorization_code_expiration='1m' WHERE client_id='c1'`)
	require.NoError(t, err)
	state := &FederationState{ClientID: "c1", RedirectURI: "http://localhost/cb", Scope: "openid", CodeChallenge: "challenge", CodeChallengeMethod: "S256"}
	_, err = db.GetDB().Exec(`UPDATE clients SET authorization_code_expiration='2m' WHERE client_id='c1'`)
	require.NoError(t, err)
	rr := httptest.NewRecorder()
	require.NoError(t, completeAuthFlow(rr, httptest.NewRequest(http.MethodGet, "/callback", nil), usr, state))
	require.Equal(t, http.StatusFound, rr.Code)
	target, err := url.Parse(rr.Header().Get("Location"))
	require.NoError(t, err)
	var expiry time.Time
	require.NoError(t, db.GetDB().QueryRow(`SELECT expires_at FROM auth_codes WHERE code=?`, target.Query().Get("code")).Scan(&expiry))
	require.WithinDuration(t, time.Now().Add(2*time.Minute), expiry, time.Second)
}
