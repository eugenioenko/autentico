package forwardauth

import (
	"database/sql/driver"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/stretchr/testify/require"
	"modernc.org/sqlite"
)

func TestOnlyVerifiedEmailBecomesTrustedIdentity(t *testing.T) {
	a := fixture(t)
	credential := completeLogin(t, a)
	for _, verified := range []bool{false, true, false} {
		_, err := db.GetDB().Exec(`UPDATE users SET is_email_verified=? WHERE id='user'`, verified)
		require.NoError(t, err)
		r := req(a, "/check")
		r.AddCookie(credential)
		r.Header.Set("X-Auth-Email", "forged@example.test")
		w := httptest.NewRecorder()
		HandleCheck(w, r)
		require.Equal(t, 204, w.Code)
		require.Equal(t, "user", w.Header().Get("X-Auth-User"))
		if verified {
			require.Equal(t, "user@test.com", w.Header().Get("X-Auth-Email"))
		} else {
			require.Empty(t, w.Header().Get("X-Auth-Email"))
		}
	}
}

func TestFlowEvictionUsesAuthenticatedAgeNotRequestOrder(t *testing.T) {
	a := fixture(t)
	sc, err := codec()
	require.NoError(t, err)
	cookies := []*http.Cookie{}
	for i := range 6 {
		c, f, _ := start(t, a)
		f.ExpiresAt = time.Now().Add(flowAge - time.Duration(6-i)*5*time.Second).Unix()
		c.Value, err = sc.Encode(c.Name, f)
		require.NoError(t, err)
		cookies = append(cookies, c)
	}
	r := req(a, a.route("start")+"?return=%2Freports")
	for i := len(cookies) - 1; i >= 0; i-- {
		r.AddCookie(cookies[i])
	}
	junk := flowName(a, strings.Repeat("a", 43))
	r.AddCookie(&http.Cookie{Name: junk, Value: "not-an-authenticated-flow"})
	w := httptest.NewRecorder()
	HandleStart(w, r)
	require.Equal(t, 303, w.Code)
	removed := map[string]bool{}
	for _, c := range w.Result().Cookies() {
		if c.MaxAge < 0 {
			removed[c.Name] = true
		}
	}
	require.True(t, removed[cookies[0].Name])
	require.True(t, removed[junk])
	require.Len(t, removed, 2)
}

func TestPendingFlowsBoundCompleteEncodedCookieHeader(t *testing.T) {
	a := fixture(t)
	jar := map[string]*http.Cookie{}
	for range 9 {
		dest := "/reports?query=" + strings.Repeat("x", 1000)
		r := req(a, a.route("start")+"?return="+url.QueryEscape(dest))
		for _, c := range jar {
			r.AddCookie(c)
		}
		w := httptest.NewRecorder()
		HandleStart(w, r)
		require.Equal(t, 303, w.Code)
		for _, c := range w.Result().Cookies() {
			if c.MaxAge < 0 {
				delete(jar, c.Name)
			} else {
				jar[c.Name] = c
			}
		}
		size := 0
		for _, c := range jar {
			size += len(c.Name) + 1 + len(c.Value) + 2
			var f loginFlow
			sc, err := codec()
			require.NoError(t, err)
			require.NoError(t, sc.Decode(c.Name, c.Value, &f))
			require.Equal(t, dest, f.Return)
		}
		require.LessOrEqual(t, size, flowCookieBudget)
		require.NotEmpty(t, jar)
		require.Less(t, len(jar), 6)
	}
	for _, length := range []int{3000, 4000} {
		r := req(a, a.route("start")+"?return="+url.QueryEscape("/reports?query="+strings.Repeat("x", length)))
		w := httptest.NewRecorder()
		HandleStart(w, r)
		require.Equal(t, 400, w.Code)
		require.Empty(t, w.Result().Cookies())
	}
}

func TestCodeExpiringAfterValidationRollsBackRedemption(t *testing.T) {
	// Pause a real SQLite read after initial code validation, then let the
	// actual deadline pass. The writer transaction must reject and roll back.
	var reads atomic.Int32
	reached, release := make(chan struct{}), make(chan struct{})
	var unblock sync.Once
	function := fmt.Sprintf("expiry_client_read_%d", time.Now().UnixNano())
	require.NoError(t, sqlite.RegisterScalarFunction(function, 0, func(_ *sqlite.FunctionContext, _ []driver.Value) (driver.Value, error) {
		if reads.Add(1) == 2 {
			close(reached)
			select {
			case <-release:
			case <-time.After(8 * time.Second):
				return nil, fmt.Errorf("test read hold timed out")
			}
		}
		return int64(1), nil
	}))
	a := fixture(t)
	c, f, state := start(t, a)
	grant := code(t, a, f)
	expires := time.Now().UTC().Add(2 * time.Second)
	_, err := db.GetDB().Exec(`UPDATE auth_codes SET expires_at=? WHERE code=?`, expires, grant)
	require.NoError(t, err)
	_, err = db.GetDB().Exec(`ALTER TABLE clients RENAME TO expiry_clients; CREATE VIEW clients AS SELECT * FROM expiry_clients WHERE ` + function + `()=1`)
	require.NoError(t, err)
	r := req(a, a.route("callback")+"?code="+grant+"&state="+state)
	r.AddCookie(c)
	done := make(chan struct{})
	w := httptest.NewRecorder()
	go func() { defer close(done); HandleCallback(w, r) }()
	defer func() {
		unblock.Do(func() { close(release) })
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("callback did not exit")
		}
	}()
	select {
	case <-reached:
	case <-done:
		t.Fatalf("callback exited before the held read: %d %s", w.Code, w.Body.String())
	case <-time.After(5 * time.Second):
		t.Fatal("callback did not reach the held read")
	}
	time.Sleep(time.Until(expires) + 25*time.Millisecond)
	unblock.Do(func() { close(release) })
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("callback did not finish")
	}
	require.Equal(t, 400, w.Code, w.Body.String())
	require.Zero(t, count(t))
	var used bool
	require.NoError(t, db.GetDB().QueryRow(`SELECT used FROM auth_codes WHERE code=?`, grant).Scan(&used))
	require.False(t, used)
	for _, cookie := range w.Result().Cookies() {
		require.NotEqual(t, a.cookieName(), cookie.Name)
	}
}
