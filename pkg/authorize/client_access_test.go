package authorize

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestHandleAuthorize_SSOAccessCheckFailureIsServerError(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "c1", []string{"http://localhost/cb"})
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthSsoEnabled = true
		config.Values.AuthSsoSessionIdleTimeout = 24 * time.Hour
		config.Values.AuthSsoSessionMaxAge = 24 * time.Hour
		config.Bootstrap.AuthIdpSessionCookieName = "autentico_idp_session"
	})
	_, err := db.GetDB().Exec(`INSERT INTO users (id, username, email, password) VALUES ('u-sso', 'sso', 'sso@test.com', 'hashed')`)
	require.NoError(t, err)
	require.NoError(t, idpsession.CreateIdpSession(idpsession.IdpSession{ID: "idp-sso", UserID: "u-sso", UserAgent: "ua", IPAddress: "127.0.0.1"}))
	_, err = db.GetDB().Exec(`UPDATE clients SET restrict_access = TRUE WHERE client_id = 'c1'`)
	require.NoError(t, err)
	_, err = db.GetDB().Exec(`DROP TABLE client_allowed_users`)
	require.NoError(t, err)

	for _, prompt := range []string{"", "none"} {
		target := "/oauth2/authorize?response_type=code&client_id=c1&redirect_uri=http://localhost/cb&state=s1&code_challenge=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk&code_challenge_method=S256"
		if prompt != "" {
			target += "&prompt=" + prompt
		}
		req := httptest.NewRequest(http.MethodGet, target, nil)
		req.AddCookie(&http.Cookie{Name: "autentico_idp_session", Value: "idp-sso"})
		rr := httptest.NewRecorder()
		HandleAuthorize(rr, req)

		require.Equal(t, http.StatusFound, rr.Code, "prompt=%q", prompt)
		location, err := url.Parse(rr.Header().Get("Location"))
		require.NoError(t, err)
		require.Equal(t, "server_error", location.Query().Get("error"), "prompt=%q", prompt)
		require.Equal(t, "s1", location.Query().Get("state"))
		require.Empty(t, location.Query().Get("code"))
	}
}
