package authorize

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestAuthorizeClientSignupOverride(t *testing.T) {
	for _, allow := range []bool{false, true} {
		t.Run(map[bool]string{false: "deny", true: "allow"}[allow], func(t *testing.T) {
			testutils.WithTestDB(t)
			testutils.InsertTestClient(t, "override", []string{"http://localhost/cb"})
			testutils.WithConfigOverride(t, func() { config.Values.AuthAllowSelfSignup = !allow })
			_, err := db.GetDB().Exec(`UPDATE clients SET allow_self_signup=? WHERE client_id='override'`, allow)
			require.NoError(t, err)
			for _, prompt := range []string{"", "create"} {
				q := url.Values{"client_id": {"override"}, "redirect_uri": {"http://localhost/cb"}, "response_type": {"code"}, "code_challenge": {"challenge"}, "code_challenge_method": {"S256"}, "prompt": {prompt}}
				rr := httptest.NewRecorder()
				HandleAuthorize(rr, httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil))
				require.Equal(t, http.StatusOK, rr.Code)
				if prompt == "" {
					require.Equal(t, allow, strings.Contains(rr.Body.String(), "Create account"))
				} else {
					require.Equal(t, allow, strings.Contains(rr.Body.String(), "confirm_password"))
				}
			}
		})
	}
}

func TestAuthorizeClientIdleOverride(t *testing.T) {
	for _, tc := range []struct {
		name     string
		global   time.Duration
		override any
		allowed  bool
	}{
		{"stricter", 30 * time.Minute, "1m", false}, {"longer", time.Minute, "30m", true}, {"infinite", time.Minute, "0", true}, {"inherit", 30 * time.Minute, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testutils.WithTestDB(t)
			testutils.InsertTestUser(t, "user-1")
			testutils.InsertTestClient(t, "override", []string{"http://localhost/cb"})
			testutils.WithConfigOverride(t, func() {
				config.Values.AuthSsoEnabled = true
				config.Values.AuthSsoSessionIdleTimeout = tc.global
				config.Values.AuthSsoSessionMaxAge = 0
				config.Bootstrap.AuthIdpSessionCookieName = "idp"
			})
			_, err := db.GetDB().Exec(`UPDATE clients SET sso_session_idle_timeout=? WHERE client_id='override'`, tc.override)
			require.NoError(t, err)
			require.NoError(t, idpsession.CreateIdpSession(idpsession.IdpSession{ID: "sso", UserID: "user-1"}))
			lastActivity := time.Now().Add(-2 * time.Minute).UTC()
			_, err = db.GetDB().Exec(`UPDATE idp_sessions SET last_activity_at=? WHERE id='sso'`, lastActivity)
			require.NoError(t, err)
			q := url.Values{"client_id": {"override"}, "redirect_uri": {"http://localhost/cb"}, "response_type": {"code"}, "code_challenge": {"challenge"}, "code_challenge_method": {"S256"}, "prompt": {"none"}}
			req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil)
			req.AddCookie(&http.Cookie{Name: "idp", Value: "sso"})
			rr := httptest.NewRecorder()
			HandleAuthorize(rr, req)
			require.Equal(t, http.StatusFound, rr.Code)
			target, err := url.Parse(rr.Header().Get("Location"))
			require.NoError(t, err)
			if tc.allowed {
				require.NotEmpty(t, target.Query().Get("code"))
				require.Empty(t, target.Query().Get("error"))
			} else {
				require.Equal(t, "login_required", target.Query().Get("error"))
			}
		})
	}
}
