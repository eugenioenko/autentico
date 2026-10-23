package session

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/rs/xid"
	"github.com/stretchr/testify/require"
)

func TestMalformedLogoutParametersAndClientMismatchCompleteLocalLogoutWithoutRedirect(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "logout-user")
	const clientID = "logout-parse-client"
	const callback = "https://client.example/signed-out"
	createTestClient(t, clientID, []string{callback})
	hint, _, err := generateTestAccessTokenWithAzp("logout-user", "different-client")
	require.NoError(t, err)
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		for _, raw := range []string{
			"id_token_hint=%ZZ&client_id=" + clientID + "&post_logout_redirect_uri=" + url.QueryEscape(callback),
			"id_token_hint=%&client_id=" + clientID + "&post_logout_redirect_uri=" + url.QueryEscape(callback),
			"state=%ZZ&client_id=" + clientID + "&post_logout_redirect_uri=" + url.QueryEscape(callback),
			url.Values{"id_token_hint": {hint}, "client_id": {clientID}, "post_logout_redirect_uri": {callback}}.Encode(),
		} {
			sessionID := xid.New().String()
			require.NoError(t, idpsession.CreateIdpSession(idpsession.IdpSession{ID: sessionID, UserID: "logout-user"}))
			var req *http.Request
			if method == http.MethodGet {
				req = httptest.NewRequest(method, "/oauth2/logout?"+raw, nil)
			} else {
				req = httptest.NewRequest(method, "/oauth2/logout", strings.NewReader(raw))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			req.AddCookie(&http.Cookie{Name: config.GetBootstrap().AuthIdpSessionCookieName, Value: sessionID})
			rr := httptest.NewRecorder()
			if method == http.MethodGet {
				HandleRpInitiatedLogout(rr, req)
			} else {
				HandleLogout(rr, req)
			}
			require.Equal(t, http.StatusOK, rr.Code)
			require.Empty(t, rr.Header().Get("Location"))
			require.Contains(t, rr.Body.String(), "signed out")
			var deactivated bool
			require.NoError(t, db.GetDB().QueryRow(`SELECT deactivated_at IS NOT NULL FROM idp_sessions WHERE id=?`, sessionID).Scan(&deactivated))
			require.True(t, deactivated)
			cleared := false
			for _, cookie := range rr.Result().Cookies() {
				if cookie.Name == config.GetBootstrap().AuthIdpSessionCookieName && cookie.MaxAge < 0 {
					cleared = true
				}
			}
			require.True(t, cleared)
		}
	}
}
