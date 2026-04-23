package testutils

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func AssertPostAuthInvariants(t *testing.T, rr *httptest.ResponseRecorder, userID string) {
	t.Helper()

	require.Equal(t, http.StatusFound, rr.Code)

	loc := rr.Header().Get("Location")
	locURL, err := url.Parse(loc)
	require.NoError(t, err)
	codeStr := locURL.Query().Get("code")
	require.NotEmpty(t, codeStr, "redirect should contain a code parameter")

	var idpSessionID string
	err = db.GetDB().QueryRow(
		`SELECT idp_session_id FROM auth_codes WHERE code = ?`, codeStr,
	).Scan(&idpSessionID)
	require.NoError(t, err, "auth code should exist in DB")
	assert.NotEmpty(t, idpSessionID, "auth code should have idp_session_id set")

	var dbUserID string
	err = db.GetDB().QueryRow(
		`SELECT user_id FROM idp_sessions WHERE id = ?`, idpSessionID,
	).Scan(&dbUserID)
	require.NoError(t, err, "IdP session should exist in DB")
	assert.Equal(t, userID, dbUserID, "IdP session should belong to the authenticated user")

	cookieName := config.GetBootstrap().AuthIdpSessionCookieName
	var sessionCookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == cookieName {
			sessionCookie = c
			break
		}
	}
	require.NotNil(t, sessionCookie, "IdP session cookie should be set")
	assert.Equal(t, idpSessionID, sessionCookie.Value, "cookie value should match auth code's idp_session_id")
	assert.True(t, sessionCookie.HttpOnly, "IdP session cookie should be HttpOnly")
}
