package session

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	"github.com/eugenioenko/autentico/pkg/key"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/xid"
	"github.com/stretchr/testify/require"
)

func TestLogoutInvalidHintNeverRedirects(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "logout-user")
	const clientID = "invalid-hint-client"
	const callback = "https://client.example/logout"
	createTestClient(t, clientID, []string{callback})
	claims := jwt.MapClaims{"sub": "logout-user", "azp": clientID, "aud": clientID, "exp": time.Now().Add(-time.Hour).Unix()}
	foreignKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	foreign, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(foreignKey)
	require.NoError(t, err)
	unsigned, err := jwt.NewWithClaims(jwt.SigningMethodNone, claims).SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)
	publicBytes, err := x509.MarshalPKIXPublicKey(key.GetPublicKey())
	require.NoError(t, err)
	hmac, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(publicBytes)
	require.NoError(t, err)
	expired, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key.GetPrivateKey())
	require.NoError(t, err)
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		for _, withClient := range []bool{false, true} {
			for name, hint := range map[string]string{"malformed": "garbage", "foreign": foreign, "unsigned": unsigned, "hmac": hmac, "expired": expired, "absent": ""} {
				t.Run(method+"/"+name+map[bool]string{false: "/no-client", true: "/client"}[withClient], func(t *testing.T) {
					sessionID := xid.New().String()
					require.NoError(t, idpsession.CreateIdpSession(idpsession.IdpSession{ID: sessionID, UserID: "logout-user"}))
					form := url.Values{"post_logout_redirect_uri": {callback}, "state": {"opaque-state"}}
					if hint != "" {
						form.Set("id_token_hint", hint)
					}
					if withClient {
						form.Set("client_id", clientID)
					}
					var req *http.Request
					if method == http.MethodGet {
						req = httptest.NewRequest(method, "/oauth2/logout?"+form.Encode(), nil)
					} else {
						req = httptest.NewRequest(method, "/oauth2/logout", strings.NewReader(form.Encode()))
						req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					}
					req.AddCookie(&http.Cookie{Name: config.GetBootstrap().AuthIdpSessionCookieName, Value: sessionID})
					rr := httptest.NewRecorder()
					if method == http.MethodGet {
						HandleRpInitiatedLogout(rr, req)
					} else {
						HandleLogout(rr, req)
					}
					wantRedirect := name == "expired" || name == "absent" && withClient
					if wantRedirect {
						require.Equal(t, http.StatusFound, rr.Code)
						require.Equal(t, callback+"?state=opaque-state", rr.Header().Get("Location"))
					} else {
						require.Equal(t, http.StatusOK, rr.Code)
						require.Empty(t, rr.Header().Get("Location"))
						require.Contains(t, rr.Body.String(), "signed out")
					}
					var deactivated bool
					require.NoError(t, db.GetDB().QueryRow(`SELECT deactivated_at IS NOT NULL FROM idp_sessions WHERE id=?`, sessionID).Scan(&deactivated))
					require.True(t, deactivated)
					var cleared bool
					for _, cookie := range rr.Result().Cookies() {
						if cookie.Name == config.GetBootstrap().AuthIdpSessionCookieName && cookie.MaxAge < 0 {
							cleared = true
						}
					}
					require.True(t, cleared)
				})
			}
		}
	}
}
