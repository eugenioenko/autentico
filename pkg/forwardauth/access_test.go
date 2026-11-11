package forwardauth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func restrictApp(t *testing.T, a *App, groups, users []string) {
	t.Helper()
	restrict := true
	require.NoError(t, client.UpdateClient(a.ClientID, client.ClientUpdateRequest{RestrictAccess: &restrict, AllowedGroups: &groups, AllowedUsers: &users}))
}

func login(t *testing.T, a *App) *http.Cookie {
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
	t.Fatal("no session cookie")
	return nil
}

func check(a *App, session *http.Cookie) *httptest.ResponseRecorder {
	r := req(a, "/check?redirect=1")
	r.Header.Set("Accept", "text/html")
	if session != nil {
		r.AddCookie(session)
	}
	w := httptest.NewRecorder()
	HandleCheck(w, r)
	return w
}

func TestForwardAuthAllowedGroupMemberPasses(t *testing.T) {
	a := fixture(t)
	testutils.InsertTestGroup(t, "g-ops", "ops")
	testutils.InsertTestGroupMembership(t, "user", "g-ops")
	restrictApp(t, a, []string{"g-ops"}, []string{})
	session := login(t, a)
	w := check(a, session)
	require.Equal(t, 204, w.Code, w.Body.String())
	require.Equal(t, "user", w.Header().Get("X-Auth-User"))
}

func TestForwardAuthCallbackRefusesUserOutsideAllowedLists(t *testing.T) {
	a := fixture(t)
	restrictApp(t, a, []string{}, []string{})
	c, f, state := start(t, a)
	r := req(a, a.route("callback")+"?code="+code(t, a, f)+"&state="+state)
	r.AddCookie(c)
	w := httptest.NewRecorder()
	HandleCallback(w, r)
	require.Equal(t, 403, w.Code)
	require.Equal(t, 0, count(t), "a refused user must not receive an application session")
	for _, cookie := range w.Result().Cookies() {
		require.NotEqual(t, a.cookieName(), cookie.Name)
	}
}

func TestForwardAuthCallbackAccessDeniedErrorIsForbidden(t *testing.T) {
	a := fixture(t)
	c, _, state := start(t, a)
	r := req(a, a.route("callback")+"?error=access_denied&state="+state)
	r.AddCookie(c)
	w := httptest.NewRecorder()
	HandleCallback(w, r)
	require.Equal(t, 403, w.Code)
	require.Empty(t, w.Header().Get("WWW-Authenticate"))

	c, _, state = start(t, a)
	r = req(a, a.route("callback")+"?error=login_required&state="+state)
	r.AddCookie(c)
	w = httptest.NewRecorder()
	HandleCallback(w, r)
	require.Equal(t, 401, w.Code)
}

func TestForwardAuthCheckRevokesAccessImmediatelyWithoutLoginLoop(t *testing.T) {
	a := fixture(t)
	testutils.InsertTestGroup(t, "g-ops", "ops")
	testutils.InsertTestGroupMembership(t, "user", "g-ops")
	restrictApp(t, a, []string{"g-ops"}, []string{})
	session := login(t, a)
	require.Equal(t, 204, check(a, session).Code)

	_, err := db.GetDB().Exec(`DELETE FROM user_groups WHERE user_id = 'user' AND group_id = 'g-ops'`)
	require.NoError(t, err)
	w := check(a, session)
	require.Equal(t, 403, w.Code)
	require.Empty(t, w.Header().Get("X-Auth-User"))
	require.Empty(t, w.Header().Get("X-Autentico-Login"), "a refused user must not be redirected back to login")
	require.Empty(t, w.Header().Get("Location"))

	testutils.InsertTestGroupMembership(t, "user", "g-ops")
	require.Equal(t, 204, check(a, session).Code)
}

func TestForwardAuthUnauthenticatedStillRedirectsToLogin(t *testing.T) {
	a := fixture(t)
	restrictApp(t, a, []string{}, []string{})
	w := check(a, nil)
	require.Equal(t, http.StatusSeeOther, w.Code)
	require.NotEmpty(t, w.Header().Get("X-Autentico-Login"))
}

func TestForwardAuthDirectUserAllowed(t *testing.T) {
	a := fixture(t)
	restrictApp(t, a, []string{}, []string{"user"})
	session := login(t, a)
	require.Equal(t, 204, check(a, session).Code)
	restrictApp(t, a, []string{}, []string{})
	require.Equal(t, 403, check(a, session).Code)
}
