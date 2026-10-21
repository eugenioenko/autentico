package session

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestLogoutRedirectPreservesOpaqueStateAndCallbackQuery(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		for _, callback := range []string{"https://example.com/signed-out", "https://example.com/signed-out?existing=a%26b&repeat=1&repeat=2"} {
			for _, state := range []string{"plain", "a&injected=1", "space + %25 #fragment /?=é", ""} {
				t.Run(method+"/"+callback+"/"+state, func(t *testing.T) {
					testutils.WithTestDB(t)
					createTestClient(t, "state-client", []string{callback})
					form := url.Values{"client_id": {"state-client"}, "post_logout_redirect_uri": {callback}, "state": {state}}
					rr := httptest.NewRecorder()
					if method == http.MethodGet {
						req := httptest.NewRequest(method, "/oauth2/logout?"+form.Encode(), nil)
						HandleRpInitiatedLogout(rr, req)
					} else {
						req := httptest.NewRequest(method, "/oauth2/logout", strings.NewReader(form.Encode()))
						req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
						HandleLogout(rr, req)
					}
					require.Equal(t, http.StatusFound, rr.Code)
					target, err := url.Parse(rr.Header().Get("Location"))
					require.NoError(t, err)
					require.Equal(t, "https", target.Scheme)
					require.Equal(t, "example.com", target.Host)
					require.Equal(t, "/signed-out", target.Path)
					require.Empty(t, target.Fragment)
					query := target.Query()
					stateParams := 0
					if state != "" {
						require.Equal(t, []string{state}, query["state"])
						stateParams = 1
					} else {
						require.NotContains(t, query, "state")
					}
					if callback == "https://example.com/signed-out" {
						require.Len(t, query, stateParams)
					} else {
						require.Len(t, query, 2+stateParams)
						require.Equal(t, []string{"a&b"}, query["existing"])
						require.Equal(t, []string{"1", "2"}, query["repeat"])
					}
				})
			}
		}
	}
}

func TestLogoutMalformedRegisteredCallbackDoesNotRedirect(t *testing.T) {
	testutils.WithTestDB(t)
	callback := "https://example.com/%zz"
	createTestClient(t, "invalid-state-client", []string{callback})
	query := url.Values{"client_id": {"invalid-state-client"}, "post_logout_redirect_uri": {callback}, "state": {"opaque"}}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/oauth2/logout?"+query.Encode(), nil)
	HandleRpInitiatedLogout(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	require.Empty(t, rr.Header().Get("Location"))
	require.Contains(t, rr.Body.String(), "signed out")
}
