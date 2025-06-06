package auth_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/session"
	"github.com/eugenioenko/autentico/pkg/token"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/userinfo"
	testutils "github.com/eugenioenko/autentico/tests/utils"

	"github.com/stretchr/testify/assert"
)

const (
	testEmail    = "johndoe@mail.com"
	testPassword = "password"
)

func TestLoginWithCredentials(t *testing.T) {
	testutils.WithTestDB(t)
	_, err := user.CreateUser(testEmail, testPassword, testEmail)
	assert.NoError(t, err)

	_, err = user.AuthenticateUser(testEmail, testPassword)
	assert.NoError(t, err)
}

func TestTokenEndpointWithPasswordRefreshAsJSON(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthRefreshTokenAsSecureCookie = false
	})
	_, _ = user.CreateUser(testEmail, testPassword, testEmail)

	body := map[string]string{
		"grant_type": "password",
		"username":   testEmail,
		"password":   testPassword,
	}
	res := testutils.MockFormRequest(t, body, http.MethodPost, "/oauth2/token", token.HandleToken)

	var tokenResponse token.TokenResponse
	err := json.Unmarshal(res.Body.Bytes(), &tokenResponse)
	assert.NoError(t, err)
	assert.NotEmpty(t, tokenResponse.AccessToken)
	assert.NotEmpty(t, tokenResponse.RefreshToken)
}

func TestTokenEndpointWithPasswordRefreshAsCookie(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthRefreshTokenAsSecureCookie = true
	})
	_, _ = user.CreateUser(testEmail, testPassword, testEmail)

	body := map[string]string{
		"grant_type": "password",
		"username":   testEmail,
		"password":   testPassword,
	}
	res := testutils.MockFormRequest(t, body, http.MethodPost, "/oauth2/token", token.HandleToken)

	var tokenResponse token.TokenResponse
	err := json.Unmarshal(res.Body.Bytes(), &tokenResponse)
	assert.NoError(t, err)
	assert.NotEmpty(t, tokenResponse.AccessToken)
	assert.Empty(t, tokenResponse.RefreshToken)
}

func TestRevokeToken(t *testing.T) {
	testutils.WithTestDB(t)
	_, _ = user.CreateUser(testEmail, testPassword, testEmail)
	authUser, _ := user.AuthenticateUser(testEmail, testPassword)
	authToken, _ := token.GenerateTokens(*authUser)
	_ = token.CreateToken(token.Token{
		UserID:       authToken.UserID,
		AccessToken:  authToken.AccessToken,
		RefreshToken: authToken.RefreshToken,
	})

	body := map[string]string{
		"token": authToken.AccessToken,
	}
	res := testutils.MockFormRequest(t, body, http.MethodPost, "/oauth2/revoke", token.HandleRevoke)

	assert.Equal(t, http.StatusOK, res.Code)
}

func TestUserInfoEndpoint(t *testing.T) {
	testutils.WithTestDB(t)
	user, _ := user.CreateUser(testEmail, testPassword, testEmail)

	body := map[string]string{
		"grant_type": "password",
		"username":   testEmail,
		"password":   testPassword,
	}
	res := testutils.MockFormRequest(t, body, http.MethodPost, "/oauth2/token", token.HandleToken)

	var token token.TokenResponse
	_ = json.Unmarshal(res.Body.Bytes(), &token)

	res = testutils.MockApiRequestWithAuth(t, "", http.MethodGet, "/oauth2/userinfo", userinfo.HandleUserInfo, token.AccessToken)
	var userInfo map[string]interface{}
	err := json.Unmarshal(res.Body.Bytes(), &userInfo)
	assert.NoError(t, err)
	assert.Equal(t, user.ID, userInfo["sub"])
}

func TestTokenEndpointRefresh(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthRefreshTokenAsSecureCookie = false
	})
	_, _ = user.CreateUser(testEmail, testPassword, testEmail)

	body := map[string]string{
		"grant_type": "password",
		"username":   testEmail,
		"password":   testPassword,
	}
	res := testutils.MockFormRequest(t, body, http.MethodPost, "/oauth2/token", token.HandleToken)

	var tkn token.TokenResponse
	_ = json.Unmarshal(res.Body.Bytes(), &tkn)

	body = map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": tkn.RefreshToken,
	}
	refreshRes := testutils.MockFormRequest(t, body, http.MethodPost, "/oauth2/token", token.HandleToken)

	var response token.TokenResponse
	err := json.Unmarshal(refreshRes.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.TokenType)
}

func TestLogoutEndpoint(t *testing.T) {
	testutils.WithTestDB(t)
	_, _ = user.CreateUser(testEmail, testPassword, testEmail)
	authUser, _ := user.AuthenticateUser(testEmail, testPassword)

	authToken, _ := token.GenerateTokens(*authUser)
	_ = token.CreateToken(token.Token{
		UserID:       authToken.UserID,
		AccessToken:  authToken.AccessToken,
		RefreshToken: authToken.RefreshToken,
	})

	res := testutils.MockApiRequestWithAuth(t, "", http.MethodPost, "/oauth2/logout", session.HandleLogout, authToken.AccessToken)
	assert.Equal(t, "{\"data\":\"ok\"}\n", res.Body.String())
}
