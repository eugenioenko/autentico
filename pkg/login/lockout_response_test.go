package login

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/user"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestBrowserLoginHidesAccountLockout(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() { config.Values.AuthAccountLockoutMaxAttempts = 2 })
	testutils.InsertTestClient(t, "lockout-client", []string{"http://localhost/callback"})
	usr, err := user.CreateUser("locked-user", "correct-password", "locked@example.com")
	require.NoError(t, err)
	_, err = db.GetDB().Exec(`UPDATE users SET failed_login_attempts=2,locked_until=? WHERE id=?`, time.Now().Add(time.Hour), usr.ID)
	require.NoError(t, err)
	request := func(username, password string) *httptest.ResponseRecorder {
		form := url.Values{"client_id": {"lockout-client"}, "redirect_uri": {"http://localhost/callback"}, "scope": {"openid"}, "username": {username}, "password": {password}}
		signLoginForm(form)
		r := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response := httptest.NewRecorder()
		HandleLoginUser(response, r)
		return response
	}
	unknown := request("unknown-user", "wrong-password")
	require.Equal(t, http.StatusFound, unknown.Code)
	target, err := url.Parse(unknown.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "Invalid username or password", target.Query().Get("error"))
	for _, password := range []string{"wrong-password", "correct-password"} {
		locked := request("locked-user", password)
		require.Equal(t, unknown.Code, locked.Code)
		require.Equal(t, unknown.Header().Get("Location"), locked.Header().Get("Location"))
	}
	current, err := user.UserByID(usr.ID)
	require.NoError(t, err)
	require.Equal(t, 2, current.FailedLoginAttempts)
	require.NotNil(t, current.LockedUntil)
	var count int
	require.NoError(t, db.GetDB().QueryRow(`SELECT count(*) FROM auth_codes`).Scan(&count))
	require.Zero(t, count)
}
