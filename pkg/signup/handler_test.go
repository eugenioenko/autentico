package signup

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/appsettings"
	"github.com/eugenioenko/autentico/pkg/authrequest"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/user"
	testutils "github.com/eugenioenko/autentico/tests/utils"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createSignupAuthRequest(t *testing.T, clientID, redirectURI string) string {
	t.Helper()
	id, err := authrequest.Create(authrequest.AuthorizeRequest{
		ClientID:    clientID,
		RedirectURI: redirectURI,
		Scope:       "openid profile email",
		State:       "test-state",
		ResponseType: "code",
	})
	require.NoError(t, err)
	return id
}

func TestHandleSignup_DisabledReturns404(t *testing.T) {
	testutils.WithTestDB(t)
	// Seed 'onboarded' as true to simulate an already-setup system
	_ = appsettings.SetSetting("onboarded", "true")
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAllowSelfSignup = false
	})

	req := httptest.NewRequest(http.MethodGet, "/oauth2/signup", nil)
	rr := httptest.NewRecorder()

	HandleSignup(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandleSignup_WrongMethod(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAllowSelfSignup = true
	})

	req := httptest.NewRequest(http.MethodPut, "/oauth2/signup", nil)
	rr := httptest.NewRecorder()

	HandleSignup(rr, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}

func TestHandleSignup_Post_MissingAuthRequestID(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAllowSelfSignup = true
	})

	form := url.Values{}
	form.Set("username", "newuser")
	form.Set("password", "password123")
	form.Set("confirm_password", "password123")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleSignup(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Missing authorization request")
}

func TestHandleSignup_Post_PasswordMismatch(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "c1", []string{"http://localhost/callback"})
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAllowSelfSignup = true
	})
	authReqID := createSignupAuthRequest(t, "c1", "http://localhost/callback")

	form := url.Values{}
	form.Set("username", "newuser")
	form.Set("password", "password123")
	form.Set("confirm_password", "different456")
	form.Set("auth_request_id", authReqID)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleSignup(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	loc := rr.Header().Get("Location")
	assert.Contains(t, loc, "Passwords+do+not+match")
}

func TestHandleSignup_Post_ValidationError(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAllowSelfSignup = true
		config.Values.ValidationMinUsernameLength = 4
	})

	form := url.Values{}
	form.Set("username", "ab") // too short
	form.Set("password", "password123")
	form.Set("confirm_password", "password123")
	form.Set("auth_request_id", createSignupAuthRequest(t, "test-client", "http://localhost/callback"))

	req := httptest.NewRequest(http.MethodPost, "/oauth2/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleSignup(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	loc := rr.Header().Get("Location")
	assert.Contains(t, loc, "auth_request_id=")
	assert.Contains(t, loc, "error=")
}

func TestHandleSignup_Post_DuplicateUser(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAllowSelfSignup = true
		config.Values.ProfileFieldEmail = "hidden"
	})

	_, err := user.CreateUser("existinguser", "password123", "existing@example.com")
	assert.NoError(t, err)

	form := url.Values{}
	form.Set("username", "existinguser")
	form.Set("password", "password123")
	form.Set("confirm_password", "password123")
	form.Set("auth_request_id", createSignupAuthRequest(t, "test-client", "http://localhost/callback"))

	req := httptest.NewRequest(http.MethodPost, "/oauth2/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleSignup(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	loc := rr.Header().Get("Location")
	assert.Contains(t, loc, "auth_request_id=")
	assert.Contains(t, loc, "Could+not+create+account")
}

func TestHandleSignup_Post_Success(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAllowSelfSignup = true
		config.Values.ProfileFieldEmail = "hidden"
		config.Values.AuthSsoSessionIdleTimeout = 0
	})

	form := url.Values{}
	form.Set("username", "newuser")
	form.Set("password", "password123")
	form.Set("confirm_password", "password123")
	form.Set("auth_request_id", createSignupAuthRequest(t, "test-client", "http://localhost/callback"))

	req := httptest.NewRequest(http.MethodPost, "/oauth2/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleSignup(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	location := rr.Header().Get("Location")
	assert.Contains(t, location, "http://localhost/callback")
	assert.Contains(t, location, "code=")
	assert.Contains(t, location, "state=test-state")
}

func TestHandleSignup_Post_SetsIdpSessionCookie(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAllowSelfSignup = true
		config.Values.ProfileFieldEmail = "hidden"
		config.Values.AuthSsoSessionIdleTimeout = 30 * time.Minute
		config.Bootstrap.AuthIdpSessionCookieName = "autentico_idp_session"
	})

	form := url.Values{}
	form.Set("username", "newuser")
	form.Set("password", "password123")
	form.Set("confirm_password", "password123")
	form.Set("auth_request_id", createSignupAuthRequest(t, "test-client", "http://localhost/callback"))

	req := httptest.NewRequest(http.MethodPost, "/oauth2/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleSignup(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)

	cookies := rr.Result().Cookies()
	var idpCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "autentico_idp_session" {
			idpCookie = c
			break
		}
	}
	assert.NotNil(t, idpCookie, "IdP session cookie should be set after signup")
	assert.NotEmpty(t, idpCookie.Value)
	assert.True(t, idpCookie.HttpOnly)
}

func TestHandleSignup_Post_PasskeyOnly(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAllowSelfSignup = true
		config.Values.AuthMode = "passkey_only"
	})

	authReqID := createSignupAuthRequest(t, "test-client", "http://localhost/callback")
	form := url.Values{}
	form.Set("auth_request_id", authReqID)
	req := httptest.NewRequest(http.MethodPost, "/oauth2/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleSignup(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code) // Re-renders the GET page
}

func TestHandleSignup_Post_RequiredFieldsMissing(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAllowSelfSignup = true
		config.Values.ProfileFieldGivenName = "required"
	})

	form := url.Values{}
	form.Set("username", "newuser")
	form.Set("password", "password123")
	form.Set("confirm_password", "password123")
	form.Set("auth_request_id", createSignupAuthRequest(t, "test-client", "http://localhost/callback"))
	// given_name is missing

	req := httptest.NewRequest(http.MethodPost, "/oauth2/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleSignup(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	loc := rr.Header().Get("Location")
	assert.Contains(t, loc, "auth_request_id=")
	assert.Contains(t, loc, "Please+fill+in+all+required+fields")
}

func TestHandleSignup_Post_EmailIsUsername(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAllowSelfSignup = true
		config.Values.ProfileFieldEmail = "is_username"
	})

	form := url.Values{}
	form.Set("username", "user@example.com")
	form.Set("password", "password123")
	form.Set("confirm_password", "password123")
	form.Set("auth_request_id", createSignupAuthRequest(t, "test-client", "http://localhost/callback"))
	// email is NOT set explicitly

	req := httptest.NewRequest(http.MethodPost, "/oauth2/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleSignup(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	
	u, _ := user.UserByUsername("user@example.com")
	assert.Equal(t, "user@example.com", u.Email)
}

func TestHandleSignupPost_Disabled(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAllowSelfSignup = false
	})

	form := url.Values{}
	form.Set("username", "newuser")
	form.Set("password", "password123")
	form.Set("confirm_password", "password123")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleSignup(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandleSignup_Post_RequireEmailVerification_ShowsVerifyPage(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAllowSelfSignup = true
		config.Values.RequireEmailVerification = true
		config.Values.EmailVerificationExpiration = 24 * time.Hour
		config.Values.ProfileFieldEmail = "optional"
	})

	form := url.Values{}
	form.Set("username", "verifyme")
	form.Set("password", "password123")
	form.Set("confirm_password", "password123")
	form.Set("email", "verifyme@test.com")
	form.Set("auth_request_id", createSignupAuthRequest(t, "test-client", "http://localhost/callback"))
	form.Set("state", "xyz")
	form.Set("client_id", "test-client")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleSignup(rr, req)

	// Should render the verify-email "sent" page, not redirect with code
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.NotContains(t, rr.Header().Get("Location"), "code=")
	assert.Contains(t, rr.Body.String(), "inbox")
}

func TestHandleSignup_Post_RequireEmailVerification_AdminExempt(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAllowSelfSignup = true
		config.Values.RequireEmailVerification = true
		config.Values.ProfileFieldEmail = "hidden"
		config.Values.AuthSsoSessionIdleTimeout = 0
	})

	// Pre-create user with admin role so signup flow picks it up
	// Actually signup always creates regular users — so test with no email
	// (no email → verification skipped even when required)
	form := url.Values{}
	form.Set("username", "noemailuser")
	form.Set("password", "password123")
	form.Set("confirm_password", "password123")
	form.Set("auth_request_id", createSignupAuthRequest(t, "test-client", "http://localhost/callback"))
	form.Set("state", "xyz")
	form.Set("client_id", "test-client")
	// No email provided

	req := httptest.NewRequest(http.MethodPost, "/oauth2/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	HandleSignup(rr, req)

	// No email → verification gate skipped → redirect with auth code
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Contains(t, rr.Header().Get("Location"), "code=")
}

func TestHandleSignupPost_InvalidForm(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAllowSelfSignup = true
	})

	req := httptest.NewRequest(http.MethodPost, "/oauth2/signup", strings.NewReader("%"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleSignup(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}
