package emailverification

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

func TestVerificationUsesCurrentClientCodeLifetime(t *testing.T) {
	withVerificationTestDB(t)
	testutils.WithConfigOverride(t, func() { config.Values.AuthAuthorizationCodeExpiration = 10 * time.Minute })
	usr, err := user.CreateUser("lifetime-user", "Password123!", "lifetime@example.com")
	require.NoError(t, err)
	raw, hash, err := GenerateToken()
	require.NoError(t, err)
	require.NoError(t, user.SetEmailVerificationToken(usr.ID, hash, time.Now().Add(time.Hour)))
	_, err = db.GetDB().Exec(`UPDATE clients SET authorization_code_expiration='1m' WHERE client_id='test-client'`)
	require.NoError(t, err)
	q := url.Values{"token": {raw}, "client_id": {"test-client"}, "redirect_uri": {"http://localhost/callback"}, "scope": {"openid"}}
	signVerificationParams(q)
	_, err = db.GetDB().Exec(`UPDATE clients SET authorization_code_expiration='2m' WHERE client_id='test-client'`)
	require.NoError(t, err)
	rr := httptest.NewRecorder()
	HandleVerifyEmail(rr, httptest.NewRequest(http.MethodGet, "/oauth2/verify-email?"+q.Encode(), nil))
	require.Equal(t, http.StatusFound, rr.Code)
	target, err := url.Parse(rr.Header().Get("Location"))
	require.NoError(t, err)
	var expiry time.Time
	require.NoError(t, db.GetDB().QueryRow(`SELECT expires_at FROM auth_codes WHERE code=?`, target.Query().Get("code")).Scan(&expiry))
	require.WithinDuration(t, time.Now().Add(2*time.Minute), expiry, time.Second)
}
