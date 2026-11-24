package e2e

import (
	"encoding/json"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/signupinvite"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestAdminInviteWithPublicSignupClosed(t *testing.T) {
	ts := startTestServer(t)
	_, admin := createTestAdmin(t, ts, "invite-admin", "password123", "admin@example.org")
	config.Values.AuthAllowSelfSignup = false
	config.Values.ProfileFieldEmail = "hidden"
	req, err := http.NewRequest("POST", ts.BaseURL+"/admin/api/signup-invites", strings.NewReader(`{"kind":"personal","delivery_method":"link"}`))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+admin)
	res, err := ts.Client.Do(req)
	require.NoError(t, err)
	var out struct{ Data signupinvite.Created }
	require.Equal(t, 201, res.StatusCode)
	require.NoError(t, json.NewDecoder(res.Body).Decode(&out))
	res.Body.Close()
	res, err = ts.Client.Get(out.Data.URL)
	require.NoError(t, err)
	res.Body.Close()
	require.Equal(t, 303, res.StatusCode)
	form := url.Values{"prompt": {"create"}, "response_type": {"code"}, "redirect_uri": {"http://localhost:3000/account/callback"}, "client_id": {config.AccountClientID}, "code_challenge": {testCodeChallenge}, "code_challenge_method": {"S256"}, "invite_id": {out.Data.ID}, "state": {"invite-test"}}
	res, err = ts.Client.Get(ts.BaseURL + "/oauth2/authorize?" + form.Encode())
	require.NoError(t, err)
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	res.Body.Close()
	require.Equal(t, 200, res.StatusCode, string(body))
	form.Set("authorize_sig", getAuthorizeSig(string(body)))
	form.Set("gorilla.csrf.Token", getCSRFToken(string(body)))
	form.Set("username", "invited-user")
	form.Set("password", "password123")
	form.Set("confirm_password", "password123")
	res, err = ts.Client.PostForm(ts.BaseURL+"/oauth2/signup", form)
	require.NoError(t, err)
	res.Body.Close()
	require.Equal(t, 302, res.StatusCode)
	usr, err := user.UserByUsername("invited-user")
	require.NoError(t, err)
	require.Equal(t, "user", usr.Role)
	require.False(t, usr.IsEmailVerified)
	res, err = ts.Client.Get(out.Data.URL)
	require.NoError(t, err)
	res.Body.Close()
	require.Equal(t, 410, res.StatusCode)
}
