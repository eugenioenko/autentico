package session

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/rs/xid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setClientURI(t *testing.T, clientID, clientURI string) {
	t.Helper()
	_, err := db.GetDB().Exec(`UPDATE clients SET client_uri = ? WHERE client_id = ?`, clientURI, clientID)
	require.NoError(t, err)
}

func logoutPage(t *testing.T, params url.Values) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/oauth2/logout?"+params.Encode(), nil)
	rr := httptest.NewRecorder()
	HandleRpInitiatedLogout(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	return rr.Body.String()
}

func TestLogoutSuccess_DefaultLink(t *testing.T) {
	testutils.WithTestDB(t)

	body := logoutPage(t, nil)
	assert.Contains(t, body, `href="/account/"`)
	assert.Contains(t, body, "Go to your profile")
}

func TestLogoutSuccess_SettingURL(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.LogoutSuccessURL = "https://app.example.com/"
	})

	body := logoutPage(t, nil)
	assert.Contains(t, body, `href="https://app.example.com/"`)
	assert.Contains(t, body, "Continue")
	assert.NotContains(t, body, `href="/account/"`)
}

func TestLogoutSuccess_SettingURLAndLabel(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.LogoutSuccessURL = "https://app.example.com/"
		config.Values.LogoutSuccessLabel = "Back to Example"
	})

	body := logoutPage(t, nil)
	assert.Contains(t, body, `href="https://app.example.com/"`)
	assert.Contains(t, body, "Back to Example")
}

func TestLogoutSuccess_SettingLabelOnly(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.LogoutSuccessLabel = "My account"
	})

	body := logoutPage(t, nil)
	assert.Contains(t, body, `href="/account/"`)
	assert.Contains(t, body, "My account")
}

func TestLogoutSuccess_ClientURIWinsOverSetting(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.LogoutSuccessURL = "https://fallback.example.com/"
		config.Values.LogoutSuccessLabel = "Fallback"
	})
	clientID := "logout-link-client"
	createTestClient(t, clientID, nil)
	setClientURI(t, clientID, "https://wiki.example.com")

	body := logoutPage(t, url.Values{"client_id": {clientID}})
	assert.Contains(t, body, `href="https://wiki.example.com"`)
	assert.Contains(t, body, "Return to Test Client "+clientID)
	assert.NotContains(t, body, "fallback.example.com")
}

func TestLogoutSuccess_ClientURIFromIdTokenHint(t *testing.T) {
	testutils.WithTestDB(t)
	userID := xid.New().String()
	_, err := db.GetDB().Exec(`INSERT INTO users (id, username, email, password) VALUES (?, ?, ?, ?)`,
		userID, "linkhintuser", "linkhint@example.com", "hash")
	require.NoError(t, err)
	clientID := "logout-link-hint-client"
	createTestClient(t, clientID, nil)
	setClientURI(t, clientID, "https://hint.example.com")
	token, _, err := generateTestAccessTokenWithAzp(userID, clientID)
	require.NoError(t, err)

	body := logoutPage(t, url.Values{"id_token_hint": {token}})
	assert.Contains(t, body, `href="https://hint.example.com"`)
}

func TestLogoutSuccess_UnregisteredRedirectStillLinksClient(t *testing.T) {
	testutils.WithTestDB(t)
	clientID := "logout-link-unregistered"
	createTestClient(t, clientID, []string{"https://allowed.example.com/out"})
	setClientURI(t, clientID, "https://app.example.com")

	body := logoutPage(t, url.Values{
		"client_id":                {clientID},
		"post_logout_redirect_uri": {"https://evil.example.com/steal"},
	})
	assert.Contains(t, body, `href="https://app.example.com"`)
	assert.NotContains(t, body, "evil.example.com")
}

func TestLogoutSuccess_ClientWithoutURIFallsBack(t *testing.T) {
	testutils.WithTestDB(t)
	clientID := "logout-link-no-uri"
	createTestClient(t, clientID, nil)

	body := logoutPage(t, url.Values{"client_id": {clientID}})
	assert.Contains(t, body, `href="/account/"`)
}

func TestLogoutSuccess_UnknownClientFallsBack(t *testing.T) {
	testutils.WithTestDB(t)

	body := logoutPage(t, url.Values{"client_id": {"nope"}})
	assert.Contains(t, body, `href="/account/"`)
}

func TestLogoutSuccess_InactiveClientFallsBack(t *testing.T) {
	testutils.WithTestDB(t)
	clientID := "logout-link-inactive"
	createTestClient(t, clientID, nil)
	setClientURI(t, clientID, "https://inactive.example.com")
	_, err := db.GetDB().Exec(`UPDATE clients SET is_active = 0 WHERE client_id = ?`, clientID)
	require.NoError(t, err)

	body := logoutPage(t, url.Values{"client_id": {clientID}})
	assert.NotContains(t, body, "inactive.example.com")
	assert.Contains(t, body, `href="/account/"`)
}

func TestLogoutSuccess_ClientIdMismatchIgnoresClientURI(t *testing.T) {
	// RP-Initiated Logout 1.0 §4: a failed client_id / id_token_hint check must
	// not be trusted for anything client-specific, including the fallback link.
	testutils.WithTestDB(t)
	userID := xid.New().String()
	_, err := db.GetDB().Exec(`INSERT INTO users (id, username, email, password) VALUES (?, ?, ?, ?)`,
		userID, "linkmismatch", "linkmismatch@example.com", "hash")
	require.NoError(t, err)
	token, _, err := generateTestAccessTokenWithAzp(userID, "real-client")
	require.NoError(t, err)
	clientID := "logout-link-wrong"
	createTestClient(t, clientID, nil)
	setClientURI(t, clientID, "https://wrong.example.com")

	body := logoutPage(t, url.Values{"id_token_hint": {token}, "client_id": {clientID}})
	assert.NotContains(t, body, "wrong.example.com")
	assert.Contains(t, body, `href="/account/"`)
}

func TestLogoutSuccess_ClientNameIsEscaped(t *testing.T) {
	testutils.WithTestDB(t)
	clientID := "logout-link-escape"
	_, err := db.GetDB().Exec(`
		INSERT INTO clients (id, client_id, client_name, client_type, redirect_uris,
		                     post_logout_redirect_uris, grant_types, response_types,
		                     scopes, token_endpoint_auth_method, is_active, client_uri)
		VALUES (?, ?, ?, 'public', '["https://example.com/callback"]', '[]',
		        '["authorization_code"]', '["code"]', 'openid', 'none', 1, ?)
	`, xid.New().String(), clientID, `<script>x</script>`, "https://app.example.com")
	require.NoError(t, err)

	body := logoutPage(t, url.Values{"client_id": {clientID}})
	assert.NotContains(t, body, "<script>x</script>")
	assert.Contains(t, body, "&lt;script&gt;")
}
