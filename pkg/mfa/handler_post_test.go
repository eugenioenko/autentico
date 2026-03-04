package mfa

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/user"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
)

func TestHandleMfaPost_EmailWrongCode(t *testing.T) {
	testutils.WithTestDB(t)
	u, _ := user.CreateUser("mfauser", "pass", "mfa@example.com")
	
	c := MfaChallenge{
		ID:         "chall1",
		UserID:     u.ID,
		Method:     "email",
		Code:       "correct_hashed",
		LoginState: `{"redirect_uri":"http://localhost/cb","state":"s1"}`,
		ExpiresAt:  time.Now().Add(time.Hour),
	}
	_ = CreateMfaChallenge(c)

	form := url.Values{}
	form.Set("challenge_id", "chall1")
	form.Set("code", "wrong")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/mfa", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleMfa(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid verification code")
}

func TestHandleMfaPost_EmailEmptyUserEmail(t *testing.T) {
	testutils.WithTestDB(t)
	// Create user with EMPTY email (using raw SQL because CreateUser validates it)
	_, _ = db.GetDB().Exec("INSERT INTO users (id, username, email, password) VALUES ('u1', 'noemail', '', 'pass')")
	
	c := MfaChallenge{
		ID:         "chall1",
		UserID:     "u1",
		Method:     "email",
		Code:       "hashed",
		LoginState: `{"redirect_uri":"http://localhost/cb","state":"s1"}`,
		ExpiresAt:  time.Now().Add(time.Hour),
	}
	_ = CreateMfaChallenge(c)

	form := url.Values{}
	form.Set("challenge_id", "chall1")
	form.Set("code", "123456")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/mfa", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleMfa(rr, req)

	// Implementation might return 400, 500 or redirect to error
	assert.NotEqual(t, http.StatusFound, rr.Code)
}
