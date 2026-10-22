package consent

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestConsentUsesCurrentClientCodeLifetime(t *testing.T) {
	testutils.WithTestDB(t)
	setupConsentClient(t, "c1")
	sid := createIdpSession(t, "user-1")
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AuthIdpSessionCookieName = testCookieName
		config.Values.AuthAuthorizationCodeExpiration = 10 * time.Minute
	})
	_, err := db.GetDB().Exec(`UPDATE clients SET authorization_code_expiration='1m' WHERE client_id='c1'`)
	require.NoError(t, err)
	params := ConsentParams{ClientID: "c1", RedirectURI: "http://localhost/callback", Scope: "openid", CodeChallenge: "challenge", CodeChallengeMethod: "S256"}
	form := url.Values{"client_id": {params.ClientID}, "redirect_uri": {params.RedirectURI}, "scope": {params.Scope}, "code_challenge": {params.CodeChallenge}, "code_challenge_method": {params.CodeChallengeMethod}, "consent_sig": {signConsent(params, "user-1")}, "action": {"allow"}}
	// Current configuration wins even when the consent page was prepared earlier.
	_, err = db.GetDB().Exec(`UPDATE clients SET authorization_code_expiration='2m' WHERE client_id='c1'`)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/oauth2/consent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: testCookieName, Value: sid})
	rr := httptest.NewRecorder()
	HandleConsent(rr, req)
	require.Equal(t, http.StatusFound, rr.Code)
	target, err := url.Parse(rr.Header().Get("Location"))
	require.NoError(t, err)
	var expiry time.Time
	require.NoError(t, db.GetDB().QueryRow(`SELECT expires_at FROM auth_codes WHERE code=?`, target.Query().Get("code")).Scan(&expiry))
	require.WithinDuration(t, time.Now().Add(2*time.Minute), expiry, time.Second)
}

func TestConsentRevalidatesRegistrationBeforePersisting(t *testing.T) {
	for _, policy := range []string{"scope", "code grant", "public PKCE", "inactive"} {
		t.Run(policy, func(t *testing.T) {
			testutils.WithTestDB(t)
			setupConsentClient(t, "c1")
			sid := createIdpSession(t, "user-1")
			testutils.WithConfigOverride(t, func() { config.Bootstrap.AuthIdpSessionCookieName = testCookieName })
			params := ConsentParams{ClientID: "c1", RedirectURI: "http://localhost/callback", Scope: "openid", CodeChallenge: "challenge", CodeChallengeMethod: "S256"}
			if policy == "public PKCE" {
				_, err := db.GetDB().Exec(`UPDATE clients SET client_type='confidential' WHERE client_id='c1'`)
				require.NoError(t, err)
				params.CodeChallenge = ""
				params.CodeChallengeMethod = ""
			}
			form := url.Values{"action": {"allow"}, "client_id": {params.ClientID}, "redirect_uri": {params.RedirectURI}, "scope": {params.Scope}, "code_challenge": {params.CodeChallenge}, "code_challenge_method": {params.CodeChallengeMethod}, "consent_sig": {signConsent(params, "user-1")}}
			changes := map[string]string{"scope": "scopes='profile'", "code grant": "grant_types='[]'", "public PKCE": "client_type='public'", "inactive": "is_active=FALSE"}
			_, err := db.GetDB().Exec("UPDATE clients SET " + changes[policy] + " WHERE client_id='c1'")
			require.NoError(t, err)
			req := httptest.NewRequest(http.MethodPost, "/oauth2/consent", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(&http.Cookie{Name: testCookieName, Value: sid})
			rr := httptest.NewRecorder()
			HandleConsent(rr, req)
			require.Equal(t, http.StatusBadRequest, rr.Code)
			require.Empty(t, rr.Header().Get("Location"))
			require.Empty(t, rr.Result().Cookies())
			for _, table := range []string{"user_consents", "auth_codes"} {
				var count int
				require.NoError(t, db.GetDB().QueryRow("SELECT count(*) FROM "+table).Scan(&count))
				require.Zero(t, count, table)
			}
		})
	}
}
