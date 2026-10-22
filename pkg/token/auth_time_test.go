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
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	"github.com/eugenioenko/autentico/pkg/session"
	"github.com/eugenioenko/autentico/pkg/user"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func authenticationFixture(t *testing.T) *user.User {
	t.Helper()
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.RequireMfa = false
		config.Bootstrap.AuthRefreshTokenSecret = "authentication-time-test-secret"
	})
	testutils.InsertTestClient(t, "time-client", []string{"http://localhost/cb"})
	_, err := db.GetDB().Exec(`UPDATE clients SET grant_types='["authorization_code","refresh_token"]' WHERE client_id='time-client'`)
	require.NoError(t, err)
	created, err := user.CreateUser("time-user", "Password123!", "time@example.com")
	require.NoError(t, err)
	usr, err := user.UserByID(created.ID)
	require.NoError(t, err)
	return usr
}

func issueTimeGrant(t *testing.T, form url.Values, status int) TokenResponse {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleToken(rr, r)
	require.Equal(t, status, rr.Code, rr.Body.String())
	var response TokenResponse
	if status == http.StatusOK {
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &response))
	}
	return response
}

func tokenTimeClaim(t *testing.T, raw, claim string) int64 {
	t.Helper()
	parsed, _, err := jwt.NewParser().ParseUnverified(raw, jwt.MapClaims{})
	require.NoError(t, err)
	return int64(parsed.Claims.(jwt.MapClaims)[claim].(float64))
}

func TestCodeExchangeAndRepeatedRefreshKeepOriginalAuthenticationTime(t *testing.T) {
	usr := authenticationFixture(t)
	authenticated := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
	require.NoError(t, idpsession.CreateIdpSession(idpsession.IdpSession{ID: "original-login", UserID: usr.ID}))
	_, err := db.GetDB().Exec(`UPDATE idp_sessions SET created_at=? WHERE id='original-login'`, authenticated)
	require.NoError(t, err)
	require.NoError(t, authcode.CreateAuthCode(authcode.AuthCode{Code: "time-code", UserID: usr.ID, ClientID: "time-client",
		RedirectURI: "http://localhost/cb", Scope: "openid", IdpSessionID: "original-login", CreatedAt: authenticated,
		ExpiresAt: time.Now().Add(time.Minute), CodeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", CodeChallengeMethod: "S256"}))
	response := issueTimeGrant(t, url.Values{"grant_type": {"authorization_code"}, "client_id": {"time-client"},
		"redirect_uri": {"http://localhost/cb"}, "code": {"time-code"}, "code_verifier": {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"}}, http.StatusOK)
	for rotation := 0; rotation < 3; rotation++ {
		for _, raw := range []string{response.IDToken, response.AccessToken, response.RefreshToken} {
			require.Equal(t, authenticated.Unix(), tokenTimeClaim(t, raw, "auth_time"))
			require.Greater(t, tokenTimeClaim(t, raw, "iat"), authenticated.Unix())
		}
		response = issueTimeGrant(t, url.Values{"grant_type": {"refresh_token"}, "client_id": {"time-client"}, "refresh_token": {response.RefreshToken}}, http.StatusOK)
	}
}

func TestLegacyRefreshRecoversKnownTimeOrRequiresLogin(t *testing.T) {
	for _, kind := range []string{"browser", "initial password", "unlinked rotated", "future claim"} {
		t.Run(kind, func(t *testing.T) {
			usr := authenticationFixture(t)
			cfg := config.Get()
			issued, err := GenerateTokens(*usr, "time-client", "openid", cfg)
			require.NoError(t, err)
			now := time.Now().UTC().Truncate(time.Second)
			claims := jwt.MapClaims{"sub": usr.ID, "sid": issued.SessionID, "azp": "time-client", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
			if kind == "future claim" {
				claims["auth_time"] = now.Add(time.Minute).Unix()
			}
			raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(config.GetBootstrap().AuthRefreshTokenSecret))
			require.NoError(t, err)
			grantType := "refresh_token"
			if kind == "initial password" {
				grantType = "password"
			}
			var browserID *string
			expected := now
			if kind == "browser" {
				id := "legacy-browser"
				browserID = &id
				expected = now.Add(-time.Hour)
				require.NoError(t, idpsession.CreateIdpSession(idpsession.IdpSession{ID: id, UserID: usr.ID}))
				_, err = db.GetDB().Exec(`UPDATE idp_sessions SET created_at=? WHERE id=?`, expected, id)
				require.NoError(t, err)
			}
			require.NoError(t, CreateToken(Token{UserID: &usr.ID, ClientID: "time-client", ACR: issued.ACR,
				AccessToken: issued.AccessToken, RefreshToken: raw, AccessTokenType: "Bearer", Scope: "openid", GrantType: grantType,
				AccessTokenExpiresAt: issued.AccessExpiresAt, RefreshTokenExpiresAt: issued.RefreshExpiresAt, IssuedAt: now}))
			require.NoError(t, session.CreateSession(session.Session{ID: issued.SessionID, UserID: usr.ID,
				AccessToken: issued.AccessToken, RefreshToken: raw, ExpiresAt: issued.RefreshExpiresAt, IdpSessionID: browserID}))
			status := http.StatusOK
			if kind == "unlinked rotated" || kind == "future claim" {
				status = http.StatusBadRequest
			}
			response := issueTimeGrant(t, url.Values{"grant_type": {"refresh_token"}, "client_id": {"time-client"}, "refresh_token": {raw}}, status)
			if status == http.StatusOK {
				require.Equal(t, expected.Unix(), tokenTimeClaim(t, response.IDToken, "auth_time"))
				response = issueTimeGrant(t, url.Values{"grant_type": {"refresh_token"}, "client_id": {"time-client"}, "refresh_token": {response.RefreshToken}}, http.StatusOK)
				require.Equal(t, expected.Unix(), tokenTimeClaim(t, response.IDToken, "auth_time"))
			} else {
				var count int
				require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM tokens WHERE revoked_at IS NULL`).Scan(&count))
				require.Equal(t, 1, count, "a metadata rejection must not consume the original credential")
			}
		})
	}
}
