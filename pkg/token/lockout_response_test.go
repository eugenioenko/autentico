package token

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

func TestPasswordGrantHidesAccountLockout(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAccountLockoutMaxAttempts = 2
		config.Values.RequireMfa = false
		config.Values.RequireEmailVerification = false
	})
	insertROPCTestClient(t)
	usr, err := user.CreateUser("locked-user", "correct-password", "locked@example.com")
	require.NoError(t, err)
	_, err = db.GetDB().Exec(`UPDATE users SET failed_login_attempts=2,locked_until=? WHERE id=?`, time.Now().Add(time.Hour), usr.ID)
	require.NoError(t, err)
	request := func(username, password string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(url.Values{"grant_type": {"password"}, "client_id": {"ropc-test-client"}, "username": {username}, "password": {password}, "scope": {"openid"}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response := httptest.NewRecorder()
		HandleToken(response, r)
		return response
	}
	unknown := request("unknown-user", "wrong-password")
	require.Equal(t, http.StatusBadRequest, unknown.Code)
	require.Contains(t, unknown.Body.String(), "invalid_grant")
	for _, password := range []string{"wrong-password", "correct-password"} {
		locked := request("locked-user", password)
		require.Equal(t, unknown.Code, locked.Code)
		require.Equal(t, unknown.Body.String(), locked.Body.String())
	}
	current, err := user.UserByID(usr.ID)
	require.NoError(t, err)
	require.Equal(t, 2, current.FailedLoginAttempts)
	require.NotNil(t, current.LockedUntil)
	for _, table := range []string{"tokens", "sessions"} {
		var count int
		require.NoError(t, db.GetDB().QueryRow(`SELECT count(*) FROM `+table).Scan(&count))
		require.Zero(t, count)
	}
	require.NoError(t, user.UnlockUser(usr.ID))
	require.Equal(t, http.StatusOK, request("locked-user", "correct-password").Code)
}
