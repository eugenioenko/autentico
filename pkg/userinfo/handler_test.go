package userinfo

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/token"
	"github.com/eugenioenko/autentico/pkg/user"
	testutils "github.com/eugenioenko/autentico/tests/utils"

	"github.com/stretchr/testify/assert"
)

func TestHandleUserInfo(t *testing.T) {
	testutils.WithTestDB(t)

	// Create a test user and token
	testUser, _ := user.CreateUser("testuser", "password123", "testuser@example.com")
	authToken := token.Token{
		UserID:               testUser.ID,
		AccessToken:          "access-token",
		AccessTokenExpiresAt: time.Now().Add(1 * time.Hour),
	}
	_ = token.CreateToken(authToken)

	// Perform user info request
	req := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer access-token")
	rr := httptest.NewRecorder()

	HandleUserInfo(rr, req)

	// Verify the response
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), testUser.Email)
	assert.Contains(t, rr.Body.String(), testUser.Username)
}
