package passkey

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

func TestPasskeyUsesCurrentClientCodeLifetime(t *testing.T) {
	withPasskeyTestDB(t)
	withPasskeyConfig(t)
	testutils.WithConfigOverride(t, func() { config.Values.AuthAuthorizationCodeExpiration = 10 * time.Minute })
	created, err := user.CreateUser("lifetime-user", "Password123!", "lifetime@example.com")
	require.NoError(t, err)
	usr, err := user.UserByID(created.ID)
	require.NoError(t, err)
	_, err = db.GetDB().Exec(`UPDATE clients SET authorization_code_expiration='1m' WHERE client_id='c1'`)
	require.NoError(t, err)
	state := `{"client_id":"c1","redirect_uri":"http://localhost/cb","scope":"openid","code_challenge":"challenge","code_challenge_method":"S256"}`
	_, err = db.GetDB().Exec(`UPDATE clients SET authorization_code_expiration='2m' WHERE client_id='c1'`)
	require.NoError(t, err)
	targetRaw, err := completeAuthFlow(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/finish", nil), usr, state)
	require.NoError(t, err)
	target, err := url.Parse(targetRaw)
	require.NoError(t, err)
	var expiry time.Time
	require.NoError(t, db.GetDB().QueryRow(`SELECT expires_at FROM auth_codes WHERE code=?`, target.Query().Get("code")).Scan(&expiry))
	require.WithinDuration(t, time.Now().Add(2*time.Minute), expiry, time.Second)
}
