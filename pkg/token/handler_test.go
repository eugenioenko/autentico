package token

import (
	"autentico/pkg/config"
	"autentico/pkg/user"
	testutils "autentico/tests/utils"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHandleToken(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthRefreshTokenAsSecureCookie = false
	})

	// Create a test user
	_, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	// Perform token request
	form := url.Values{}
	form.Add("grant_type", "password")
	form.Add("username", "testuser")
	form.Add("password", "password123")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleToken(rr, req)

	// Verify the response
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "access_token")
	assert.Contains(t, rr.Body.String(), "refresh_token")
}
