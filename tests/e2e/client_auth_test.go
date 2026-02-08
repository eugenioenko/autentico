package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfidentialClient_BasicAuth(t *testing.T) {
	ts := startTestServer(t)
	redirectURI := "http://localhost:3000/callback"

	_, adminToken := createTestAdmin(t, ts, "admin@test.com", "password123", "admin@test.com")

	clientResp := createTestClient(t, ts, adminToken, client.ClientCreateRequest{
		ClientName:   "Confidential BasicAuth",
		RedirectURIs: []string{redirectURI},
		GrantTypes:   []string{"authorization_code"},
		ClientType:   "confidential",
	})
	clientID := clientResp["client_id"].(string)
	clientSecret := clientResp["client_secret"].(string)

	createTestUser(t, "user@test.com", "password123", "user@test.com")

	code := performAuthorizationCodeFlow(t, ts, clientID, redirectURI, "user@test.com", "password123", "state1")

	// Exchange code using Basic Auth
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)

	req, err := http.NewRequest("POST", ts.BaseURL+"/oauth2/token", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "Basic Auth token exchange should succeed: %s", string(body))

	var tokens token.TokenResponse
	err = json.Unmarshal(body, &tokens)
	require.NoError(t, err)
	assert.NotEmpty(t, tokens.AccessToken)
	assert.Equal(t, "Bearer", tokens.TokenType)
}

func TestConfidentialClient_FormPost(t *testing.T) {
	ts := startTestServer(t)
	redirectURI := "http://localhost:3000/callback"

	_, adminToken := createTestAdmin(t, ts, "admin@test.com", "password123", "admin@test.com")

	clientResp := createTestClient(t, ts, adminToken, client.ClientCreateRequest{
		ClientName:   "Confidential FormPost",
		RedirectURIs: []string{redirectURI},
		GrantTypes:   []string{"authorization_code"},
		ClientType:   "confidential",
	})
	clientID := clientResp["client_id"].(string)
	clientSecret := clientResp["client_secret"].(string)

	createTestUser(t, "user@test.com", "password123", "user@test.com")

	code := performAuthorizationCodeFlow(t, ts, clientID, redirectURI, "user@test.com", "password123", "state1")

	// Exchange code using form-post client credentials
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)

	resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "form-post token exchange should succeed: %s", string(body))

	var tokens token.TokenResponse
	err = json.Unmarshal(body, &tokens)
	require.NoError(t, err)
	assert.NotEmpty(t, tokens.AccessToken)
	assert.Equal(t, "Bearer", tokens.TokenType)
}

func TestConfidentialClient_MissingSecret(t *testing.T) {
	ts := startTestServer(t)
	redirectURI := "http://localhost:3000/callback"

	_, adminToken := createTestAdmin(t, ts, "admin@test.com", "password123", "admin@test.com")

	clientResp := createTestClient(t, ts, adminToken, client.ClientCreateRequest{
		ClientName:   "Confidential NoSecret",
		RedirectURIs: []string{redirectURI},
		GrantTypes:   []string{"authorization_code"},
		ClientType:   "confidential",
	})
	clientID := clientResp["client_id"].(string)

	createTestUser(t, "user@test.com", "password123", "user@test.com")

	code := performAuthorizationCodeFlow(t, ts, clientID, redirectURI, "user@test.com", "password123", "state1")

	// Exchange code with only client_id, no secret
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", clientID)

	resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "missing secret should be rejected: %s", string(body))

	var errResp map[string]interface{}
	_ = json.Unmarshal(body, &errResp)
	assert.Equal(t, "invalid_client", errResp["error"])
}

func TestConfidentialClient_WrongSecret(t *testing.T) {
	ts := startTestServer(t)
	redirectURI := "http://localhost:3000/callback"

	_, adminToken := createTestAdmin(t, ts, "admin@test.com", "password123", "admin@test.com")

	clientResp := createTestClient(t, ts, adminToken, client.ClientCreateRequest{
		ClientName:   "Confidential WrongSecret",
		RedirectURIs: []string{redirectURI},
		GrantTypes:   []string{"authorization_code"},
		ClientType:   "confidential",
	})
	clientID := clientResp["client_id"].(string)

	createTestUser(t, "user@test.com", "password123", "user@test.com")

	code := performAuthorizationCodeFlow(t, ts, clientID, redirectURI, "user@test.com", "password123", "state1")

	// Exchange code with wrong secret via Basic Auth
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)

	req, err := http.NewRequest("POST", ts.BaseURL+"/oauth2/token", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, "completely-wrong-secret")

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "wrong secret should be rejected: %s", string(body))

	var errResp map[string]interface{}
	_ = json.Unmarshal(body, &errResp)
	assert.Equal(t, "invalid_client", errResp["error"])
}

func TestPublicClient_NoSecretRequired(t *testing.T) {
	ts := startTestServer(t)
	redirectURI := "http://localhost:3000/callback"

	_, adminToken := createTestAdmin(t, ts, "admin@test.com", "password123", "admin@test.com")

	clientResp := createTestClient(t, ts, adminToken, client.ClientCreateRequest{
		ClientName:   "Public Client",
		RedirectURIs: []string{redirectURI},
		GrantTypes:   []string{"authorization_code"},
		ClientType:   "public",
	})
	clientID := clientResp["client_id"].(string)

	createTestUser(t, "user@test.com", "password123", "user@test.com")

	code := performAuthorizationCodeFlow(t, ts, clientID, redirectURI, "user@test.com", "password123", "state1")

	// Exchange code with only client_id (no secret needed for public client)
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", clientID)

	resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "public client should succeed without secret: %s", string(body))

	var tokens token.TokenResponse
	err = json.Unmarshal(body, &tokens)
	require.NoError(t, err)
	assert.NotEmpty(t, tokens.AccessToken)
	assert.Equal(t, "Bearer", tokens.TokenType)
}

func TestInactiveClient_Rejected(t *testing.T) {
	ts := startTestServer(t)
	redirectURI := "http://localhost:3000/callback"

	_, adminToken := createTestAdmin(t, ts, "admin@test.com", "password123", "admin@test.com")

	clientResp := createTestClient(t, ts, adminToken, client.ClientCreateRequest{
		ClientName:   "Soon Inactive Client",
		RedirectURIs: []string{redirectURI},
		GrantTypes:   []string{"authorization_code"},
		ClientType:   "public",
	})
	clientID := clientResp["client_id"].(string)

	// Deactivate the client directly in the DB
	_, err := db.GetDB().Exec(`UPDATE clients SET is_active = FALSE WHERE client_id = ?`, clientID)
	require.NoError(t, err)

	// Attempt /authorize with the inactive client
	authorizeURL := ts.BaseURL + "/oauth2/authorize?" + url.Values{
		"response_type": {"code"},
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"state":         {"state1"},
	}.Encode()

	resp, err := ts.Client.Get(authorizeURL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "inactive client should be rejected at /authorize: %s", string(body))

	var errResp map[string]interface{}
	_ = json.Unmarshal(body, &errResp)
	assert.Equal(t, "invalid_client", errResp["error"])
}

func TestClient_GrantTypeRestriction(t *testing.T) {
	ts := startTestServer(t)
	redirectURI := "http://localhost:3000/callback"

	_, adminToken := createTestAdmin(t, ts, "admin@test.com", "password123", "admin@test.com")

	// Client only allows authorization_code grant
	clientResp := createTestClient(t, ts, adminToken, client.ClientCreateRequest{
		ClientName:   "Auth Code Only Client",
		RedirectURIs: []string{redirectURI},
		GrantTypes:   []string{"authorization_code"},
		ClientType:   "confidential",
	})
	clientID := clientResp["client_id"].(string)
	clientSecret := clientResp["client_secret"].(string)

	createTestUser(t, "user@test.com", "password123", "user@test.com")

	// Attempt password grant with this client — should be rejected
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", "user@test.com")
	form.Set("password", "password123")

	req, err := http.NewRequest("POST", ts.BaseURL+"/oauth2/token", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "unauthorized grant type should be rejected: %s", string(body))

	var errResp map[string]interface{}
	_ = json.Unmarshal(body, &errResp)
	assert.Equal(t, "unauthorized_client", errResp["error"])
}

func TestClient_RedirectURIEnforcement(t *testing.T) {
	ts := startTestServer(t)
	allowedURI := "http://localhost:3000/callback"
	disallowedURI := "http://evil.com/callback"

	_, adminToken := createTestAdmin(t, ts, "admin@test.com", "password123", "admin@test.com")

	clientResp := createTestClient(t, ts, adminToken, client.ClientCreateRequest{
		ClientName:   "Redirect Enforced Client",
		RedirectURIs: []string{allowedURI},
		GrantTypes:   []string{"authorization_code"},
		ClientType:   "public",
	})
	clientID := clientResp["client_id"].(string)

	// Attempt /authorize with a disallowed redirect_uri
	authorizeURL := ts.BaseURL + "/oauth2/authorize?" + url.Values{
		"response_type": {"code"},
		"client_id":     {clientID},
		"redirect_uri":  {disallowedURI},
		"state":         {"state1"},
	}.Encode()

	resp, err := ts.Client.Get(authorizeURL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "disallowed redirect_uri should be rejected: %s", string(body))

	var errResp map[string]interface{}
	_ = json.Unmarshal(body, &errResp)
	assert.Equal(t, "invalid_request", errResp["error"])
}

func TestClient_ResponseTypeRestriction(t *testing.T) {
	ts := startTestServer(t)
	redirectURI := "http://localhost:3000/callback"

	_, adminToken := createTestAdmin(t, ts, "admin@test.com", "password123", "admin@test.com")

	// Client only allows response_type "token"
	clientResp := createTestClient(t, ts, adminToken, client.ClientCreateRequest{
		ClientName:    "Token Only Client",
		RedirectURIs:  []string{redirectURI},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"token"},
		ClientType:    "public",
	})
	clientID := clientResp["client_id"].(string)

	// Attempt /authorize with response_type=code — should be rejected
	authorizeURL := ts.BaseURL + "/oauth2/authorize?" + url.Values{
		"response_type": {"code"},
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"state":         {"state1"},
	}.Encode()

	resp, err := ts.Client.Get(authorizeURL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "disallowed response_type should be rejected: %s", string(body))

	var errResp map[string]interface{}
	_ = json.Unmarshal(body, &errResp)
	assert.Equal(t, "unsupported_response_type", errResp["error"])
}
