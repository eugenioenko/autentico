package login

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/user"
	testutils "github.com/eugenioenko/autentico/tests/utils"

	"github.com/stretchr/testify/assert"
)

func TestHandleLoginUser(t *testing.T) {
	testutils.WithTestDB(t)

	// Create a test user
	_, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	assert.NoError(t, err)

	// Perform login
	form := url.Values{}
	form.Add("username", "testuser")
	form.Add("password", "password123")
	form.Add("redirect", "http://localhost/callback")
	form.Add("state", "xyz123")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleLoginUser(rr, req)

	// Verify the response
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Contains(t, rr.Header().Get("Location"), "http://localhost/callback")
	assert.Contains(t, rr.Header().Get("Location"), "code=")
	assert.Contains(t, rr.Header().Get("Location"), "state=xyz123")
}
