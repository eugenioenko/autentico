package login

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/user"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestPasswordLoginRedirectPreservesExistingQueryAndOpaqueState(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() { config.Values.RequireMfa = false; config.Values.AuthMode = "password" })
	_, err := user.CreateUser("query-login", "Password123!", "query@example.com")
	require.NoError(t, err)
	callback := "http://localhost/callback?existing=a%26b&repeat=1&repeat=2"
	state := "state & injected=1 + %25 # é"
	testutils.InsertTestClient(t, "query-client", []string{callback})
	form := url.Values{"username": {"query-login"}, "password": {"Password123!"}, "client_id": {"query-client"},
		"redirect_uri": {callback}, "scope": {"openid"}, "state": {state},
		"code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}, "code_challenge_method": {"S256"}}
	testutils.SetAuthorizeSig(form)
	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleLoginUser(rr, req)
	require.Equal(t, http.StatusFound, rr.Code)
	target, err := url.Parse(rr.Header().Get("Location"))
	require.NoError(t, err)
	require.Empty(t, target.Fragment)
	query := target.Query()
	require.Equal(t, []string{"a&b"}, query["existing"])
	require.Equal(t, []string{"1", "2"}, query["repeat"])
	require.Equal(t, []string{state}, query["state"])
	require.Len(t, query["code"], 1)
	require.Len(t, query, 4)
	var redirect string
	require.NoError(t, db.GetDB().QueryRow("SELECT redirect_uri FROM auth_codes WHERE code=?", query.Get("code")).Scan(&redirect))
	require.Equal(t, callback, redirect)
}
