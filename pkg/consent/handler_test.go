package consent

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupConsentClient(t *testing.T, clientID string) {
	t.Helper()
	testutils.InsertTestClient(t, clientID, []string{"http://localhost/callback"})
}

func createIdpSession(t *testing.T, userID string) string {
	t.Helper()
	testutils.InsertTestUser(t, userID)
	sessionID := "session-" + userID
	err := idpsession.CreateIdpSession(idpsession.IdpSession{
		ID:        sessionID,
		UserID:    userID,
		UserAgent: "test-agent",
		IPAddress: "127.0.0.1",
	})
	require.NoError(t, err)
	return sessionID
}

const testCookieName = "autentico_idp_session"

func TestHandleConsent_Get_NoSession_ReturnsUnauthorized(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AuthIdpSessionCookieName = testCookieName
	})
	setupConsentClient(t, "c1")

	req := httptest.NewRequest(http.MethodGet, "/oauth2/consent?client_id=c1&redirect_uri=http://localhost/callback&scope=openid", nil)
	rr := httptest.NewRecorder()
	HandleConsent(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "login_required")
}

func TestHandleConsent_Get_InvalidClient_ReturnsBadRequest(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AuthIdpSessionCookieName = testCookieName
	})
	sessionID := createIdpSession(t, "user1")

	req := httptest.NewRequest(http.MethodGet, "/oauth2/consent?client_id=nonexistent&redirect_uri=http://localhost/callback&scope=openid", nil)
	req.AddCookie(&http.Cookie{Name: testCookieName, Value: sessionID})
	rr := httptest.NewRecorder()
	HandleConsent(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_client")
}

func TestHandleConsent_Get_ValidRequest_RendersConsentPage(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AuthIdpSessionCookieName = testCookieName
	})
	setupConsentClient(t, "c1")
	sessionID := createIdpSession(t, "user1")

	req := httptest.NewRequest(http.MethodGet, "/oauth2/consent?client_id=c1&redirect_uri=http://localhost/callback&scope=openid+profile&state=xyz", nil)
	req.AddCookie(&http.Cookie{Name: testCookieName, Value: sessionID})
	rr := httptest.NewRecorder()
	HandleConsent(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	body := rr.Body.String()
	assert.Contains(t, body, "Authorize Access")
	assert.Contains(t, body, "consent_sig")
	assert.Contains(t, body, "Test Client")
}

func TestHandleConsent_Post_NoSession_ReturnsUnauthorized(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AuthIdpSessionCookieName = testCookieName
	})

	form := url.Values{}
	form.Set("action", "allow")
	form.Set("client_id", "c1")
	form.Set("redirect_uri", "http://localhost/callback")
	form.Set("consent_sig", "any")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/consent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleConsent(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestHandleConsent_Post_TamperedSignature_ReturnsBadRequest(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AuthIdpSessionCookieName = testCookieName
		config.Bootstrap.AuthCSRFProtectionSecretKey = "test-secret-key-for-consent-test!"
	})
	setupConsentClient(t, "c1")
	sessionID := createIdpSession(t, "user1")

	form := url.Values{}
	form.Set("action", "allow")
	form.Set("client_id", "c1")
	form.Set("redirect_uri", "http://localhost/callback")
	form.Set("scope", "openid")
	form.Set("consent_sig", "bad-signature")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/consent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: testCookieName, Value: sessionID})
	rr := httptest.NewRecorder()
	HandleConsent(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "tampered")
}

func TestHandleConsent_Post_Deny_RedirectsWithAccessDenied(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AuthIdpSessionCookieName = testCookieName
		config.Bootstrap.AuthCSRFProtectionSecretKey = "test-secret-key-for-consent-test!"
	})
	setupConsentClient(t, "c1")
	sessionID := createIdpSession(t, "user1")

	params := ConsentParams{
		ClientID:    "c1",
		RedirectURI: "http://localhost/callback",
		Scope:       "openid",
		State:       "xyz",
	}
	sig := signConsent(params, "user1")

	form := url.Values{}
	form.Set("action", "deny")
	form.Set("client_id", "c1")
	form.Set("redirect_uri", "http://localhost/callback")
	form.Set("scope", "openid")
	form.Set("state", "xyz")
	form.Set("consent_sig", sig)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/consent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: testCookieName, Value: sessionID})
	rr := httptest.NewRecorder()
	HandleConsent(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	loc, err := url.Parse(rr.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "access_denied", loc.Query().Get("error"))
	assert.Equal(t, "xyz", loc.Query().Get("state"))
	assert.Empty(t, loc.Query().Get("code"))
}

func TestHandleConsent_Post_Allow_StoresConsentAndRedirects(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AuthIdpSessionCookieName = testCookieName
		config.Bootstrap.AuthCSRFProtectionSecretKey = "test-secret-key-for-consent-test!"
	})
	setupConsentClient(t, "c1")
	sessionID := createIdpSession(t, "user1")

	params := ConsentParams{
		ClientID:            "c1",
		RedirectURI:         "http://localhost/callback",
		Scope:               "openid profile",
		State:               "abc",
		CodeChallenge:       "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		CodeChallengeMethod: "S256",
	}
	sig := signConsent(params, "user1")

	form := url.Values{}
	form.Set("action", "allow")
	form.Set("client_id", "c1")
	form.Set("redirect_uri", "http://localhost/callback")
	form.Set("scope", "openid profile")
	form.Set("state", "abc")
	form.Set("code_challenge", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
	form.Set("code_challenge_method", "S256")
	form.Set("consent_sig", sig)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/consent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: testCookieName, Value: sessionID})
	rr := httptest.NewRecorder()
	HandleConsent(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	loc, err := url.Parse(rr.Header().Get("Location"))
	require.NoError(t, err)
	assert.NotEmpty(t, loc.Query().Get("code"), "should issue auth code")
	assert.Equal(t, "abc", loc.Query().Get("state"), "state should be preserved")

	// Verify consent was stored
	uc, err := GetConsent("user1", "c1")
	require.NoError(t, err)
	require.NotNil(t, uc)
	assert.Equal(t, "openid profile", uc.Scopes)
}

func TestHandleConsent_Post_InvalidClient_ReturnsBadRequest(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AuthIdpSessionCookieName = testCookieName
		config.Bootstrap.AuthCSRFProtectionSecretKey = "test-secret-key-for-consent-test!"
	})
	sessionID := createIdpSession(t, "user1")

	params := ConsentParams{
		ClientID:    "nonexistent",
		RedirectURI: "http://localhost/callback",
		Scope:       "openid",
	}
	sig := signConsent(params, "user1")

	form := url.Values{}
	form.Set("action", "allow")
	form.Set("client_id", "nonexistent")
	form.Set("redirect_uri", "http://localhost/callback")
	form.Set("scope", "openid")
	form.Set("consent_sig", sig)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/consent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: testCookieName, Value: sessionID})
	rr := httptest.NewRecorder()
	HandleConsent(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_client")
}

func TestHandleConsent_Post_InvalidRedirectURI_ReturnsBadRequest(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AuthIdpSessionCookieName = testCookieName
		config.Bootstrap.AuthCSRFProtectionSecretKey = "test-secret-key-for-consent-test!"
	})
	setupConsentClient(t, "c1")
	sessionID := createIdpSession(t, "user1")

	params := ConsentParams{
		ClientID:    "c1",
		RedirectURI: "http://evil.com/callback",
		Scope:       "openid",
	}
	sig := signConsent(params, "user1")

	form := url.Values{}
	form.Set("action", "allow")
	form.Set("client_id", "c1")
	form.Set("redirect_uri", "http://evil.com/callback")
	form.Set("scope", "openid")
	form.Set("consent_sig", sig)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/consent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: testCookieName, Value: sessionID})
	rr := httptest.NewRecorder()
	HandleConsent(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Redirect URI not allowed")
}

func TestHandleConsent_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodDelete, "/oauth2/consent", nil)
	rr := httptest.NewRecorder()
	HandleConsent(rr, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}

func TestSignConsent_DifferentParams_DifferentSignatures(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AuthIdpSessionCookieName = testCookieName
		config.Bootstrap.AuthCSRFProtectionSecretKey = "test-secret-key-for-consent-test!"
	})

	p1 := ConsentParams{ClientID: "c1", RedirectURI: "http://localhost/cb", Scope: "openid"}
	p2 := ConsentParams{ClientID: "c2", RedirectURI: "http://localhost/cb", Scope: "openid"}

	sig1 := signConsent(p1, "user1")
	sig2 := signConsent(p2, "user1")
	assert.NotEqual(t, sig1, sig2)

	sig3 := signConsent(p1, "user2")
	assert.NotEqual(t, sig1, sig3)
}

func TestVerifyConsentSignature_ValidSignature(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AuthIdpSessionCookieName = testCookieName
		config.Bootstrap.AuthCSRFProtectionSecretKey = "test-secret-key-for-consent-test!"
	})

	params := ConsentParams{ClientID: "c1", RedirectURI: "http://localhost/cb", Scope: "openid", State: "s1"}
	sig := signConsent(params, "user1")

	assert.True(t, verifyConsentSignature(params, "user1", sig))
	assert.False(t, verifyConsentSignature(params, "user1", "tampered"))
	assert.False(t, verifyConsentSignature(params, "user2", sig))
}

func TestRedirectToConsent_BuildsCorrectURL(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AppOAuthPath = "/oauth2"
	})

	params := ConsentParams{
		ClientID:            "c1",
		RedirectURI:         "http://localhost/cb",
		Scope:               "openid profile",
		State:               "xyz",
		Nonce:               "n1",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
		Prompt:              "consent",
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	RedirectToConsent(rr, req, params)

	assert.Equal(t, http.StatusFound, rr.Code)
	loc := rr.Header().Get("Location")
	assert.Contains(t, loc, "/oauth2/consent?")
	parsed, _ := url.Parse(loc)
	assert.Equal(t, "c1", parsed.Query().Get("client_id"))
	assert.Equal(t, "openid profile", parsed.Query().Get("scope"))
	assert.Equal(t, "xyz", parsed.Query().Get("state"))
	assert.Equal(t, "n1", parsed.Query().Get("nonce"))
	assert.Equal(t, "consent", parsed.Query().Get("prompt"))
}
