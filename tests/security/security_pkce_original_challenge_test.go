package security

import (
	"io"
	"net/url"
	"strings"
	"testing"
	"time"

	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/stretchr/testify/require"
)

func TestPKCEVerifierRequiresOriginalChallenge(t *testing.T) {
	ts := startTestServer(t)
	usr := createTestUser(t, "original-challenge", "password123", "")
	require.NoError(t, authcode.CreateAuthCode(authcode.AuthCode{Code: "optional-pkce", UserID: usr.ID, ClientID: "sec-confidential", RedirectURI: "http://localhost:3000/callback", Scope: "openid", ExpiresAt: time.Now().Add(time.Minute)}))
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {"sec-confidential"}, "client_secret": {"sec-secret"}, "code": {"optional-pkce"}, "redirect_uri": {"http://localhost:3000/callback"}, "code_verifier": {strings.Repeat("a", 43)}}
	denied, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	body, err := io.ReadAll(denied.Body)
	_ = denied.Body.Close()
	require.NoError(t, err)
	require.Equal(t, 400, denied.StatusCode)
	require.Contains(t, string(body), "invalid_grant")
	stored, err := authcode.AuthCodeByCodeIncludingUsed("optional-pkce")
	require.NoError(t, err)
	require.False(t, stored.Used)
	var count int
	require.NoError(t, db.GetDB().QueryRow("SELECT count(*) FROM tokens").Scan(&count))
	require.Zero(t, count)
	form.Del("code_verifier")
	accepted, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	_ = accepted.Body.Close()
	require.Equal(t, 200, accepted.StatusCode)
	replay, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	_ = replay.Body.Close()
	require.Equal(t, 400, replay.StatusCode)
}
