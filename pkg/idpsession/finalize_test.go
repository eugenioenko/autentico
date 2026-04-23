package idpsession

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"

	"github.com/stretchr/testify/assert"
)

func TestFinalizeLogin_Success(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AuthIdpSessionCookieName = "autentico_idp_session"
		config.Bootstrap.AppOAuthPath = "/oauth2"
		config.Bootstrap.AuthIdpSessionSecureCookie = false
	})
	testutils.InsertTestUser(t, "user-1")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", "test-agent")

	sessionID := FinalizeLogin(rr, req, "user-1")

	assert.NotEmpty(t, sessionID)

	// Verify session was created in database
	var dbID string
	err := db.GetDB().QueryRow(`SELECT id FROM idp_sessions WHERE id = ?`, sessionID).Scan(&dbID)
	assert.NoError(t, err)
	assert.Equal(t, sessionID, dbID)

	// Verify cookie was set
	cookies := rr.Result().Cookies()
	assert.Len(t, cookies, 1)
	assert.Equal(t, "autentico_idp_session", cookies[0].Name)
	assert.Equal(t, sessionID, cookies[0].Value)
}

func TestFinalizeLogin_InvalidUser(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AuthIdpSessionCookieName = "autentico_idp_session"
		config.Bootstrap.AppOAuthPath = "/oauth2"
		config.Bootstrap.AuthIdpSessionSecureCookie = false
	})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	sessionID := FinalizeLogin(rr, req, "nonexistent-user")

	assert.Empty(t, sessionID)

	// Verify no cookie was set
	cookies := rr.Result().Cookies()
	assert.Empty(t, cookies)
}
