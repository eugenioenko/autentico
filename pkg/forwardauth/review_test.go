package forwardauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/stretchr/testify/require"
)

func completeLogin(t *testing.T, a *App) *http.Cookie {
	t.Helper()
	c, f, state := start(t, a)
	r := req(a, a.route("callback")+"?code="+code(t, a, f)+"&state="+state)
	r.AddCookie(c)
	w := httptest.NewRecorder()
	HandleCallback(w, r)
	require.Equal(t, 303, w.Code, w.Body.String())
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == a.cookieName() {
			return cookie
		}
	}
	t.Fatal("callback issued no app cookie")
	return nil
}

func checked(t *testing.T, a *App, c *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	r := req(a, "/check")
	r.AddCookie(c)
	w := httptest.NewRecorder()
	HandleCheck(w, r)
	return w
}

func TestStalePolicyDoesNotBlockAppAdministration(t *testing.T) {
	a := fixture(t)
	credential := completeLogin(t, a)
	config.Bootstrap.AppURL = "https://auth.other.test"
	stale, err := AppByID(a.ID)
	require.NoError(t, err)
	require.False(t, stale.validStored())
	require.Equal(t, 403, checked(t, a, credential).Code)
	_, _, err = checkSession(a, credential.Value)
	require.ErrorIs(t, err, errDenied)
	healthy, err := SaveApp("", AppRequest{Name: "Healthy", Origin: "https://app.other.test", AllowedReturnPaths: []string{"/"}})
	require.NoError(t, err)
	apps, err := ListApps()
	require.NoError(t, err)
	require.Len(t, apps, 2)
	listed := httptest.NewRecorder()
	HandleList(listed, httptest.NewRequest("GET", "/admin/api/protected-apps", nil))
	require.Equal(t, 200, listed.Code)
	require.NoError(t, DeleteApp(a.ID))
	apps, err = ListApps()
	require.NoError(t, err)
	require.Equal(t, []App{*healthy}, apps)
	var active bool
	require.NoError(t, db.GetDB().QueryRow(`SELECT is_active FROM clients WHERE client_id=?`, a.ClientID).Scan(&active))
	require.False(t, active)
}

func TestInvalidStoredPolicyCanBeRepairedAndMalformedPathsDeleted(t *testing.T) {
	for _, stored := range []string{`["/reports/../admin"]`, `{broken`} {
		t.Run(stored, func(t *testing.T) {
			a := fixture(t)
			credential := completeLogin(t, a)
			_, err := db.GetDB().Exec(`UPDATE protected_apps SET allowed_return_paths=? WHERE id=?`, stored, a.ID)
			require.NoError(t, err)
			require.GreaterOrEqual(t, checked(t, a, credential).Code, 400)
			if strings.HasPrefix(stored, "[") {
				apps, err := ListApps()
				require.NoError(t, err)
				require.Len(t, apps, 1)
				require.False(t, apps[0].validStored())
			}
			// PUT can repair paths without decoding the previous paths. Its
			// request still requires an unchanged origin and current validation.
			body, err := json.Marshal(AppRequest{Name: "Repaired", Origin: a.Origin, AllowedReturnPaths: []string{"/reports"}, SessionTTL: "1h"})
			require.NoError(t, err)
			r := httptest.NewRequest("PUT", "/admin/api/protected-apps/"+a.ID, strings.NewReader(string(body)))
			r.SetPathValue("id", a.ID)
			w := httptest.NewRecorder()
			HandleSave(w, r)
			require.Equal(t, 200, w.Code, w.Body.String())
			repaired, err := AppByID(a.ID)
			require.NoError(t, err)
			require.True(t, repaired.validStored())
			require.Equal(t, 204, checked(t, repaired, credential).Code)
			_, err = db.GetDB().Exec(`UPDATE protected_apps SET allowed_return_paths='{broken' WHERE id=?`, a.ID)
			require.NoError(t, err)
			require.NoError(t, DeleteApp(a.ID))
			require.Zero(t, count(t))
		})
	}
}

func TestRecentAccessIsReadOnlyAndActivityFailuresRollback(t *testing.T) {
	a := fixture(t)
	credential := completeLogin(t, a)
	_, err := db.GetDB().Exec(`CREATE TRIGGER reject_fa_activity BEFORE UPDATE OF last_activity_at ON forward_auth_sessions BEGIN SELECT RAISE(ABORT,'unexpected write'); END;
        CREATE TRIGGER reject_parent_activity BEFORE UPDATE OF last_activity_at ON idp_sessions BEGIN SELECT RAISE(ABORT,'unexpected write'); END;`)
	require.NoError(t, err)
	// An asset burst with fresh timestamps must not attempt either write.
	for range 20 {
		require.Equal(t, 204, checked(t, a, credential).Code)
	}
	_, err = db.GetDB().Exec(`DROP TRIGGER reject_fa_activity; DROP TRIGGER reject_parent_activity;`)
	require.NoError(t, err)
	old := time.Now().UTC().Add(-activityWriteInterval - time.Second)
	_, err = db.GetDB().Exec(`UPDATE forward_auth_sessions SET last_activity_at=?`, old)
	require.NoError(t, err)
	_, err = db.GetDB().Exec(`UPDATE idp_sessions SET last_activity_at=? WHERE id='parent'`, old)
	require.NoError(t, err)
	_, err = db.GetDB().Exec(`CREATE TRIGGER reject_parent_activity BEFORE UPDATE OF last_activity_at ON idp_sessions BEGIN SELECT RAISE(ABORT,'write failed'); END`)
	require.NoError(t, err)
	require.Equal(t, 503, checked(t, a, credential).Code)
	var last time.Time
	require.NoError(t, db.GetDB().QueryRow(`SELECT last_activity_at FROM forward_auth_sessions`).Scan(&last))
	require.True(t, old.Equal(last), "failed parent write must roll back child activity")
	_, err = db.GetDB().Exec(`DROP TRIGGER reject_parent_activity`)
	require.NoError(t, err)
	require.Equal(t, 204, checked(t, a, credential).Code)
	require.NoError(t, db.GetDB().QueryRow(`SELECT last_activity_at FROM forward_auth_sessions`).Scan(&last))
	require.WithinDuration(t, time.Now(), last, time.Second)
	require.NoError(t, db.GetDB().QueryRow(`SELECT last_activity_at FROM idp_sessions WHERE id='parent'`).Scan(&last))
	require.WithinDuration(t, time.Now(), last, time.Second)
}

func TestShortClientIdleLimitStillPersistsEachAccess(t *testing.T) {
	a := fixture(t)
	credential := completeLogin(t, a)
	_, err := db.GetDB().Exec(`UPDATE clients SET sso_session_idle_timeout='2s' WHERE client_id=?`, a.ClientID)
	require.NoError(t, err)
	old := time.Now().UTC().Add(-time.Second)
	_, err = db.GetDB().Exec(`UPDATE idp_sessions SET last_activity_at=? WHERE id='parent'`, old)
	require.NoError(t, err)
	require.Equal(t, 204, checked(t, a, credential).Code)
	var last time.Time
	require.NoError(t, db.GetDB().QueryRow(`SELECT last_activity_at FROM idp_sessions WHERE id='parent'`).Scan(&last))
	require.True(t, last.After(old))
}
