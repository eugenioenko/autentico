package token

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestPendingLegacyPKCECodeRetainsS256AfterUpgrade(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "legacy-pkce-user")
	testutils.InsertTestClient(t, "legacy-pkce-client", []string{"http://localhost/cb"})
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	require.NoError(t, authcode.CreateAuthCode(authcode.AuthCode{Code: "legacy-pkce", UserID: "legacy-pkce-user", ClientID: "legacy-pkce-client", RedirectURI: "http://localhost/cb", Scope: "openid", CodeChallenge: challenge, CodeChallengeMethod: "S256", ExpiresAt: time.Now().Add(time.Minute)}))
	// Reproduce an unchanged row issued by the previous server, not by the new
	// storage helper (which always persists the new request's effective method).
	_, err := db.GetDB().Exec(`UPDATE auth_codes SET code_challenge_method='' WHERE code='legacy-pkce'`)
	require.NoError(t, err)
	exchange := func(value string) *httptest.ResponseRecorder {
		form := url.Values{"grant_type": {"authorization_code"}, "code": {"legacy-pkce"}, "client_id": {"legacy-pkce-client"}, "redirect_uri": {"http://localhost/cb"}, "code_verifier": {value}}
		r := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		HandleToken(rr, r)
		return rr
	}
	rejected := exchange(challenge)
	require.Equal(t, http.StatusBadRequest, rejected.Code, rejected.Body.String())
	var errorBody struct {
		Error string `json:"error"`
	}
	require.NoError(t, json.Unmarshal(rejected.Body.Bytes(), &errorBody))
	require.Equal(t, "invalid_grant", errorBody.Error)
	var count int
	require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM tokens`).Scan(&count))
	require.Zero(t, count)
	code, err := authcode.AuthCodeByCodeIncludingUsed("legacy-pkce")
	require.NoError(t, err)
	require.False(t, code.Used)
	accepted := exchange(verifier)
	require.Equal(t, http.StatusOK, accepted.Code, accepted.Body.String())
	var tokens TokenResponse
	require.NoError(t, json.Unmarshal(accepted.Body.Bytes(), &tokens))
	require.NotEmpty(t, tokens.AccessToken)
}
