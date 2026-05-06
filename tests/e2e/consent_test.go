package e2e

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// postConsentForm reads hidden fields from the consent page HTML and POSTs them back.
func postConsentForm(t *testing.T, ts *TestServer, htmlBody, action string) *http.Response {
	t.Helper()
	csrfToken := getCSRFToken(htmlBody)
	require.NotEmpty(t, csrfToken)
	consentSig := getConsentSig(htmlBody)
	require.NotEmpty(t, consentSig)

	form := url.Values{}
	form.Set("action", action)
	form.Set("redirect_uri", getHiddenField(htmlBody, "redirect_uri"))
	form.Set("state", getHiddenField(htmlBody, "state"))
	form.Set("client_id", getHiddenField(htmlBody, "client_id"))
	form.Set("scope", getHiddenField(htmlBody, "scope"))
	form.Set("nonce", getHiddenField(htmlBody, "nonce"))
	form.Set("code_challenge", getHiddenField(htmlBody, "code_challenge"))
	form.Set("code_challenge_method", getHiddenField(htmlBody, "code_challenge_method"))
	form.Set("prompt", getHiddenField(htmlBody, "prompt"))
	form.Set("consent_sig", consentSig)
	form.Set("gorilla.csrf.Token", csrfToken)

	req, err := http.NewRequest("POST", ts.BaseURL+"/oauth2/consent", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", ts.BaseURL+"/oauth2/consent")

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	return resp
}

// followToConsentPage follows the consent redirect and returns the consent HTML body.
func followToConsentPage(t *testing.T, ts *TestServer, location string) string {
	t.Helper()
	consentResp, err := ts.Client.Get(ts.BaseURL + location)
	require.NoError(t, err)
	consentBody, err := io.ReadAll(consentResp.Body)
	_ = consentResp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, consentResp.StatusCode)
	return string(consentBody)
}

func seedConsentClient(t *testing.T) {
	t.Helper()
	_, err := db.GetDB().Exec(`
		INSERT INTO clients (id, client_id, client_name, client_type, redirect_uris, post_logout_redirect_uris,
			grant_types, response_types, scopes, is_active, consent_required)
		VALUES ('consent-client-id', 'consent-client', 'Consent Test Client', 'public',
			'["http://localhost:3000/callback"]', '[]',
			'["authorization_code","password","refresh_token"]', '["code"]',
			'openid profile email', TRUE, 1)
	`)
	require.NoError(t, err)
}

// performAuthFlowUntilConsent drives authorize → login and returns the consent page redirect location.
func performAuthFlowUntilConsent(t *testing.T, ts *TestServer, clientID, redirectURI, username, password, state string) string {
	t.Helper()

	authorizeURL := ts.BaseURL + "/oauth2/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"state":                 {state},
		"scope":                 {"openid profile email"},
		"code_challenge":        {testCodeChallenge},
		"code_challenge_method": {"S256"},
	}.Encode()

	resp, err := ts.Client.Get(authorizeURL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	htmlBody := string(body)
	csrfToken := getCSRFToken(htmlBody)
	require.NotEmpty(t, csrfToken)
	authorizeSig := getAuthorizeSig(htmlBody)

	form := url.Values{}
	form.Set("username", username)
	form.Set("password", password)
	form.Set("redirect_uri", redirectURI)
	form.Set("state", state)
	form.Set("client_id", clientID)
	form.Set("scope", getHiddenField(htmlBody, "scope"))
	form.Set("code_challenge", testCodeChallenge)
	form.Set("code_challenge_method", "S256")
	form.Set("gorilla.csrf.Token", csrfToken)
	form.Set("authorize_sig", authorizeSig)

	loginReq, err := http.NewRequest("POST", ts.BaseURL+"/oauth2/login", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginReq.Header.Set("Referer", ts.BaseURL+"/oauth2/authorize")

	loginResp, err := ts.Client.Do(loginReq)
	require.NoError(t, err)
	defer func() { _ = loginResp.Body.Close() }()

	require.Equal(t, http.StatusFound, loginResp.StatusCode)
	return loginResp.Header.Get("Location")
}

func TestConsentFlow_ConsentRequired_ShowsConsentScreen(t *testing.T) {
	ts := startTestServer(t)
	seedConsentClient(t)
	createTestUser(t, "consent-user", "password123", "consent@test.com")

	location := performAuthFlowUntilConsent(t, ts, "consent-client", "http://localhost:3000/callback", "consent-user", "password123", "s1")

	assert.Contains(t, location, "/consent", "login should redirect to consent screen")
	assert.NotContains(t, location, "code=", "should not issue auth code before consent")
}

func TestConsentFlow_ConsentNotRequired_SkipsConsent(t *testing.T) {
	ts := startTestServer(t)
	createTestUser(t, "noconsent-user", "password123", "noconsent@test.com")

	// test-client does not have consent_required set
	code := performAuthorizationCodeFlow(t, ts, "test-client", "http://localhost:3000/callback", "noconsent-user", "password123", "s1")
	assert.NotEmpty(t, code, "should issue auth code without consent")
}

func TestConsentFlow_Allow_IssuesAuthCode(t *testing.T) {
	ts := startTestServer(t)
	seedConsentClient(t)
	createTestUser(t, "allow-user", "password123", "allow@test.com")

	location := performAuthFlowUntilConsent(t, ts, "consent-client", "http://localhost:3000/callback", "allow-user", "password123", "s1")
	require.Contains(t, location, "/consent")

	htmlBody := followToConsentPage(t, ts, location)
	assert.Contains(t, htmlBody, "Consent Test Client", "consent page should show client name")
	assert.Contains(t, htmlBody, "Authorize Access", "consent page should show authorization title")

	allowResp := postConsentForm(t, ts, htmlBody, "allow")
	defer func() { _ = allowResp.Body.Close() }()

	require.Equal(t, http.StatusFound, allowResp.StatusCode)
	redirectURL, err := url.Parse(allowResp.Header.Get("Location"))
	require.NoError(t, err)
	assert.NotEmpty(t, redirectURL.Query().Get("code"), "consent allow should issue auth code")
	assert.Equal(t, "s1", redirectURL.Query().Get("state"), "state should be preserved")
}

func TestConsentFlow_Deny_ReturnsAccessDenied(t *testing.T) {
	ts := startTestServer(t)
	seedConsentClient(t)
	createTestUser(t, "deny-user", "password123", "deny@test.com")

	location := performAuthFlowUntilConsent(t, ts, "consent-client", "http://localhost:3000/callback", "deny-user", "password123", "s1")
	require.Contains(t, location, "/consent")

	htmlBody := followToConsentPage(t, ts, location)

	denyResp := postConsentForm(t, ts, htmlBody, "deny")
	defer func() { _ = denyResp.Body.Close() }()

	require.Equal(t, http.StatusFound, denyResp.StatusCode)
	redirectURL, err := url.Parse(denyResp.Header.Get("Location"))
	require.NoError(t, err)

	assert.Equal(t, "access_denied", redirectURL.Query().Get("error"), "deny should return access_denied error")
	assert.Empty(t, redirectURL.Query().Get("code"), "deny should not issue auth code")
	assert.Equal(t, "s1", redirectURL.Query().Get("state"), "state should be preserved")
}

func TestConsentFlow_PreviousConsent_SkipsScreen(t *testing.T) {
	ts := startTestServer(t)
	seedConsentClient(t)
	createTestUser(t, "repeat-user", "password123", "repeat@test.com")

	// First flow: consent required, redirect to consent screen
	location := performAuthFlowUntilConsent(t, ts, "consent-client", "http://localhost:3000/callback", "repeat-user", "password123", "s1")
	require.Contains(t, location, "/consent")

	// Follow and allow consent
	htmlBody := followToConsentPage(t, ts, location)

	allowResp := postConsentForm(t, ts, htmlBody, "allow")
	_ = allowResp.Body.Close()
	require.Equal(t, http.StatusFound, allowResp.StatusCode)

	// Second flow with same scopes: SSO session active + consent already granted → direct code
	authorizeURL := ts.BaseURL + "/oauth2/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {"consent-client"},
		"redirect_uri":          {"http://localhost:3000/callback"},
		"state":                 {"s2"},
		"scope":                 {"openid profile email"},
		"code_challenge":        {testCodeChallenge},
		"code_challenge_method": {"S256"},
	}.Encode()
	resp, err := ts.Client.Get(authorizeURL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusFound, resp.StatusCode)
	redirectURL, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	code := redirectURL.Query().Get("code")
	assert.NotEmpty(t, code, "second flow with same scopes should skip consent and issue code directly")
	assert.NotContains(t, resp.Header.Get("Location"), "/consent", "should not redirect to consent")
}

func TestConsentFlow_PromptNone_ConsentRequired_ReturnsError(t *testing.T) {
	ts := startTestServer(t)
	seedConsentClient(t)
	createTestUser(t, "promptnone-user", "password123", "promptnone@test.com")

	// OIDC Core §3.1.2.1: prompt=none with consent needed should return consent_required
	authorizeURL := ts.BaseURL + "/oauth2/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {"consent-client"},
		"redirect_uri":          {"http://localhost:3000/callback"},
		"state":                 {"s1"},
		"prompt":                {"none"},
		"code_challenge":        {testCodeChallenge},
		"code_challenge_method": {"S256"},
	}.Encode()

	resp, err := ts.Client.Get(authorizeURL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// prompt=none should redirect with error (no session = login_required)
	require.Equal(t, http.StatusFound, resp.StatusCode)
	location := resp.Header.Get("Location")
	redirectURL, _ := url.Parse(location)
	errParam := redirectURL.Query().Get("error")
	assert.Contains(t, []string{"login_required", "consent_required"}, errParam)
}

func TestConsentFlow_ConsentSignatureTampering_Rejected(t *testing.T) {
	ts := startTestServer(t)
	seedConsentClient(t)
	createTestUser(t, "tamper-user", "password123", "tamper@test.com")

	location := performAuthFlowUntilConsent(t, ts, "consent-client", "http://localhost:3000/callback", "tamper-user", "password123", "s1")
	require.Contains(t, location, "/consent")

	htmlBody := followToConsentPage(t, ts, location)
	csrfToken := getCSRFToken(htmlBody)

	// POST with tampered consent_sig — all other fields from page
	form := url.Values{}
	form.Set("action", "allow")
	form.Set("redirect_uri", getHiddenField(htmlBody, "redirect_uri"))
	form.Set("state", getHiddenField(htmlBody, "state"))
	form.Set("client_id", getHiddenField(htmlBody, "client_id"))
	form.Set("scope", getHiddenField(htmlBody, "scope"))
	form.Set("nonce", getHiddenField(htmlBody, "nonce"))
	form.Set("code_challenge", getHiddenField(htmlBody, "code_challenge"))
	form.Set("code_challenge_method", getHiddenField(htmlBody, "code_challenge_method"))
	form.Set("consent_sig", "tampered-signature-value")
	form.Set("gorilla.csrf.Token", csrfToken)

	allowReq, _ := http.NewRequest("POST", ts.BaseURL+"/oauth2/consent", strings.NewReader(form.Encode()))
	allowReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	allowReq.Header.Set("Referer", ts.BaseURL+"/oauth2/consent")

	allowResp, err := ts.Client.Do(allowReq)
	require.NoError(t, err)
	defer func() { _ = allowResp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, allowResp.StatusCode, "tampered signature should be rejected")
}
