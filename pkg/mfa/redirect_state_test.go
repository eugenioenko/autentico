package mfa

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/stretchr/testify/require"
)

func TestMfaRedirectPreservesOpaqueStateAndCallbackQuery(t *testing.T) {
	for _, callback := range []string{"http://localhost/cb", "http://localhost/cb?existing=a%26b&repeat=1&repeat=2"} {
		for _, state := range []string{"plain", "a&injected=1", "space + %25 #fragment /?=é", ""} {
			t.Run(callback+"/"+state, func(t *testing.T) {
				atomicEmailChallenge(t)
				loginState, err := json.Marshal(LoginState{ClientID: "atomic-client", RedirectURI: callback, Scope: "openid", State: state, CodeChallenge: "challenge", CodeChallengeMethod: "S256"})
				require.NoError(t, err)
				_, err = db.GetDB().Exec("UPDATE mfa_challenges SET login_state=? WHERE id='atomic-challenge'", string(loginState))
				require.NoError(t, err)
				redirects, err := json.Marshal([]string{callback})
				require.NoError(t, err)
				_, err = db.GetDB().Exec("UPDATE clients SET redirect_uris=? WHERE client_id='atomic-client'", string(redirects))
				require.NoError(t, err)
				rr := postAtomicMfa()
				require.Equal(t, http.StatusFound, rr.Code)
				target, err := url.Parse(rr.Header().Get("Location"))
				require.NoError(t, err)
				require.Equal(t, "http", target.Scheme)
				require.Equal(t, "localhost", target.Host)
				require.Equal(t, "/cb", target.Path)
				require.Empty(t, target.Fragment)
				query := target.Query()
				require.Equal(t, []string{state}, query["state"])
				require.Len(t, query["code"], 1)
				var storedRedirect string
				require.NoError(t, db.GetDB().QueryRow("SELECT redirect_uri FROM auth_codes WHERE code=?", query.Get("code")).Scan(&storedRedirect))
				require.Equal(t, callback, storedRedirect)
				if callback == "http://localhost/cb" {
					require.Len(t, query, 2)
				} else {
					require.Len(t, query, 4)
					require.Equal(t, []string{"a&b"}, query["existing"])
					require.Equal(t, []string{"1", "2"}, query["repeat"])
				}
			})
		}
	}
}

func TestMfaMalformedCallbackDoesNotIssueAuthenticatedState(t *testing.T) {
	atomicEmailChallenge(t)
	state, err := json.Marshal(LoginState{ClientID: "atomic-client", RedirectURI: "http://localhost/%zz", Scope: "openid"})
	require.NoError(t, err)
	_, err = db.GetDB().Exec("UPDATE mfa_challenges SET login_state=? WHERE id='atomic-challenge'", string(state))
	require.NoError(t, err)
	rr := postAtomicMfa()
	require.Equal(t, http.StatusFound, rr.Code)
	require.Contains(t, rr.Header().Get("Location"), "/oauth2/authorize?")
	require.Empty(t, rr.Result().Cookies())
	for _, table := range []string{"auth_codes", "idp_sessions", "trusted_devices"} {
		var count int
		require.NoError(t, db.GetDB().QueryRow("SELECT COUNT(*) FROM "+table).Scan(&count))
		require.Zero(t, count, table)
	}
}
