package security

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/account"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/model"
	"github.com/eugenioenko/autentico/pkg/trusteddevice"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestAccountDeviceIDsCannotBeReplayedAsTrustedCookies(t *testing.T) {
	ts := startTestServer(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.RequireMfa = false
		config.Values.TrustDeviceEnabled = true
		config.Values.MfaMethod = "totp"
	})
	usr := createTestUser(t, "device-owner", "Password123!", "owner@example.com")
	other := createTestUser(t, "device-other", "Password123!", "other@example.com")
	access := obtainTokensViaROPC(t, ts, "autentico-account", usr.Username, "Password123!")
	require.NoError(t, user.SaveTotpSecret(usr.ID, "JBSWY3DPEHPK3PXP"))
	const token = "independent-trusted-cookie-secret"
	const publicID = "public-device-id"
	require.NoError(t, trusteddevice.CreateTrustedDevice(trusteddevice.TrustedDevice{ID: publicID, UserID: usr.ID, DeviceName: "Browser", ExpiresAt: time.Now().Add(time.Hour)}, token))
	require.NoError(t, trusteddevice.CreateTrustedDevice(trusteddevice.TrustedDevice{ID: "other-id", UserID: other.ID, ExpiresAt: time.Now().Add(time.Hour)}, "other-user-cookie"))
	status, body := doAccountRequest(t, ts, http.MethodGet, access.AccessToken, "/account/api/trusted-devices", "")
	require.Equal(t, http.StatusOK, status)
	require.NotContains(t, string(body), token)
	require.NotContains(t, string(body), utils.HashToken(token))
	require.NotContains(t, string(body), "token_hash")
	var listed model.ApiResponse[[]account.TrustedDeviceResponse]
	require.NoError(t, json.Unmarshal(body, &listed))
	require.Len(t, listed.Data, 1)
	require.Equal(t, publicID, listed.Data[0].ID)
	login := func(cookie string) string {
		browser := newClientWithJar()
		defer browser.CloseIdleConnections()
		params := url.Values{"response_type": {"code"}, "client_id": {"test-client"}, "redirect_uri": {"http://localhost:3000/callback"}, "scope": {"openid"}, "state": {"device-test"}, "code_challenge": {testCodeChallenge}, "code_challenge_method": {"S256"}}
		resp, err := browser.Get(ts.BaseURL + "/oauth2/authorize?" + params.Encode())
		require.NoError(t, err)
		page, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		require.Equal(t, http.StatusOK, resp.StatusCode)
		params.Set("username", usr.Username)
		params.Set("password", "Password123!")
		params.Set("authorize_sig", getAuthorizeSig(string(page)))
		params.Set("gorilla.csrf.Token", getCSRFToken(string(page)))
		req, err := http.NewRequest(http.MethodPost, ts.BaseURL+"/oauth2/login", strings.NewReader(params.Encode()))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Referer", ts.BaseURL+"/oauth2/authorize")
		req.AddCookie(&http.Cookie{Name: trusteddevice.CookieName, Value: cookie})
		resp, err = browser.Do(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		require.Equal(t, http.StatusFound, resp.StatusCode)
		return resp.Header.Get("Location")
	}
	for _, value := range []string{listed.Data[0].ID, utils.HashToken(token), "other-user-cookie"} {
		require.Contains(t, login(value), "/mfa?challenge_id=")
	}
	require.Contains(t, login(token), "http://localhost:3000/callback?code=")
	status, _ = doAccountRequest(t, ts, http.MethodDelete, access.AccessToken, "/account/api/trusted-devices/other-id", "")
	require.Equal(t, http.StatusForbidden, status)
	status, _ = doAccountRequest(t, ts, http.MethodDelete, access.AccessToken, "/account/api/trusted-devices/"+publicID, "")
	require.Equal(t, http.StatusOK, status)
	require.Contains(t, login(token), "/mfa?challenge_id=")
}
