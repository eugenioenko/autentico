package auth_test

import (
	"autentico/pkg/config"
	"autentico/pkg/session"
	"autentico/pkg/token"
	"autentico/pkg/user"
	"autentico/pkg/userinfo"
	testutils "autentico/tests/utils"
	"encoding/json"
	"net/http"
	"testing"

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
