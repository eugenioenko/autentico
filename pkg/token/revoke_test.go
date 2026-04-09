package token_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/token"
	"github.com/eugenioenko/autentico/pkg/user"
	testutils "github.com/eugenioenko/autentico/tests/utils"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

const (
	testEmail    = "johndoe@mail.com"
	testPassword = "password"

	revokeClientID     = "revoke-conf-client"
	revokeClientSecret = "revoke-conf-secret"
)

// setupRevokeClient creates a confidential client with ROPC support for revoke tests.
func setupRevokeClient(t *testing.T) {
	t.Helper()
	hashed, err := bcrypt.GenerateFromPassword([]byte(revokeClientSecret), bcrypt.MinCost)
	require.NoError(t, err)
	_, err = db.GetDB().Exec(
		`INSERT INTO clients (id, client_id, client_name, client_secret, client_type, redirect_uris, post_logout_redirect_uris, is_active, scopes, grant_types)
		 VALUES (?, ?, 'Revoke Test Confidential Client', ?, 'confidential', '[]', '[]', TRUE, 'openid profile email', '["authorization_code","password","refresh_token"]')`,
		"id-"+revokeClientID, revokeClientID, string(hashed),
	)
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// RFC 7009 §2.1 — Client authentication (negative tests)
// ---------------------------------------------------------------------------

// TestHandleRevoke_NoAuth_Returns401 verifies that unauthenticated revoke
// requests are rejected per RFC 7009 §2.1.
func TestHandleRevoke_NoAuth_Returns401(t *testing.T) {
	testutils.WithTestDB(t)

	body := map[string]string{"token": "some-token"}
	res := testutils.MockFormRequest(t, body, http.MethodPost, "/oauth2/revoke", token.HandleRevoke)

	assert.Equal(t, http.StatusUnauthorized, res.Code, "RFC 7009 §2.1: unauthenticated request MUST be rejected")
	assert.Contains(t, res.Body.String(), "invalid_client")
}

// TestHandleRevoke_InvalidClientCredentials_Returns401 verifies that wrong
// client credentials are rejected.
func TestHandleRevoke_InvalidClientCredentials_Returns401(t *testing.T) {
	testutils.WithTestDB(t)
	setupRevokeClient(t)

	body := map[string]string{"token": "some-token"}
	res := testutils.MockFormRequestWithBasicAuth(t, body, http.MethodPost, "/oauth2/revoke", token.HandleRevoke, revokeClientID, "wrong-secret")

	assert.Equal(t, http.StatusUnauthorized, res.Code)
	assert.Contains(t, res.Body.String(), "invalid_client")
}

// ---------------------------------------------------------------------------
// RFC 7009 §2.2 — Revocation responses (with client auth)
// ---------------------------------------------------------------------------

// TestHandleRevoke_InvalidToken_Returns200 verifies RFC 7009 §2.2:
// "The authorization server responds with HTTP status code 200 if the token
// has been revoked successfully or if the client submitted an invalid token."
func TestHandleRevoke_InvalidToken_Returns200(t *testing.T) {
	testutils.WithTestDB(t)
	setupRevokeClient(t)

	body := map[string]string{"token": "this-is-not-a-valid-jwt"}
	res := testutils.MockFormRequestWithBasicAuth(t, body, http.MethodPost, "/oauth2/revoke", token.HandleRevoke, revokeClientID, revokeClientSecret)

	assert.Equal(t, http.StatusOK, res.Code, "RFC 7009 §2.2: invalid token MUST return 200, not 4xx")
}

// TestHandleRevoke_UnknownToken_Returns200 verifies RFC 7009 §2.2 for a
// well-formed but unrecognised token (e.g. issued by a different server).
func TestHandleRevoke_UnknownToken_Returns200(t *testing.T) {
	testutils.WithTestDB(t)
	setupRevokeClient(t)

	fakeJWT := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1bmtub3duIiwiZXhwIjo5OTk5OTk5OTk5fQ.invalidsignature"
	body := map[string]string{"token": fakeJWT}
	res := testutils.MockFormRequestWithBasicAuth(t, body, http.MethodPost, "/oauth2/revoke", token.HandleRevoke, revokeClientID, revokeClientSecret)

	assert.Equal(t, http.StatusOK, res.Code, "RFC 7009 §2.2: unrecognised token MUST return 200, not 4xx")
}

func TestHandleRevoke(t *testing.T) {
	testutils.WithTestDB(t)
	_, _ = user.CreateUser(testEmail, testPassword, testEmail)

	setupRevokeClient(t)

	// Issue token via the same confidential client that will revoke it
	body := map[string]string{
		"grant_type":    "password",
		"client_id":     revokeClientID,
		"client_secret": revokeClientSecret,
		"username":      testEmail,
		"password":      testPassword,
	}
	res := testutils.MockFormRequest(t, body, http.MethodPost, "/oauth2/token", token.HandleToken)

	var tkn token.TokenResponse
	_ = json.Unmarshal(res.Body.Bytes(), &tkn)

	// Revoke the token (with client auth — same client that issued it)
	body = map[string]string{
		"token": tkn.AccessToken,
	}
	res = testutils.MockFormRequestWithBasicAuth(t, body, http.MethodPost, "/oauth2/revoke", token.HandleRevoke, revokeClientID, revokeClientSecret)

	// Verify the response
	assert.Equal(t, http.StatusOK, res.Code)

	// Verify the token is revoked
	var revokedAt string
	err := db.GetDB().QueryRow(`SELECT revoked_at FROM tokens WHERE access_token = ?`, tkn.AccessToken).Scan(&revokedAt)
	assert.NoError(t, err)
	assert.NotEmpty(t, revokedAt)
}

// RFC 7009 §2.1: token_type_hint is OPTIONAL; the server MAY ignore it.
// §2.2: an invalid token_type_hint value is ignored and does not influence the response.
func TestHandleRevoke_TokenTypeHint_Accepted(t *testing.T) {
	testutils.WithTestDB(t)
	setupRevokeClient(t)

	body := map[string]string{
		"token":           "nonexistent-token",
		"token_type_hint": "refresh_token",
	}
	res := testutils.MockFormRequestWithBasicAuth(t, body, http.MethodPost, "/oauth2/revoke", token.HandleRevoke, revokeClientID, revokeClientSecret)
	assert.Equal(t, http.StatusOK, res.Code, "RFC 7009 §2.1: token_type_hint must be accepted without error")
}

// RFC 7009 §2.2: invalid token_type_hint is ignored
func TestHandleRevoke_InvalidTokenTypeHint_Ignored(t *testing.T) {
	testutils.WithTestDB(t)
	setupRevokeClient(t)

	body := map[string]string{
		"token":           "nonexistent-token",
		"token_type_hint": "totally_invalid_hint",
	}
	res := testutils.MockFormRequestWithBasicAuth(t, body, http.MethodPost, "/oauth2/revoke", token.HandleRevoke, revokeClientID, revokeClientSecret)
	assert.Equal(t, http.StatusOK, res.Code, "RFC 7009 §2.2: invalid hint must be ignored, still return 200")
}

// RFC 7009 §2.2: revoking a refresh token SHOULD also invalidate the access token
// on the same authorization grant. Our schema stores both on the same row.
func TestHandleRevoke_RefreshToken_AlsoRevokesAccess(t *testing.T) {
	testutils.WithTestDB(t)
	_, _ = user.CreateUser(testEmail, testPassword, testEmail)

	setupRevokeClient(t)

	// Issue token via the same confidential client that will revoke it
	body := map[string]string{
		"grant_type":    "password",
		"client_id":     revokeClientID,
		"client_secret": revokeClientSecret,
		"username":      testEmail,
		"password":      testPassword,
	}
	res := testutils.MockFormRequest(t, body, http.MethodPost, "/oauth2/token", token.HandleToken)

	var tkn token.TokenResponse
	_ = json.Unmarshal(res.Body.Bytes(), &tkn)
	assert.NotEmpty(t, tkn.RefreshToken)
	assert.NotEmpty(t, tkn.AccessToken)

	// Revoke by refresh_token (with client auth — same client)
	body = map[string]string{"token": tkn.RefreshToken}
	res = testutils.MockFormRequestWithBasicAuth(t, body, http.MethodPost, "/oauth2/revoke", token.HandleRevoke, revokeClientID, revokeClientSecret)
	assert.Equal(t, http.StatusOK, res.Code)

	// Both tokens on the same row should now be revoked
	var revokedAt string
	err := db.GetDB().QueryRow(`SELECT revoked_at FROM tokens WHERE access_token = ?`, tkn.AccessToken).Scan(&revokedAt)
	assert.NoError(t, err)
	assert.NotEmpty(t, revokedAt, "RFC 7009 §2.2: revoking refresh_token must also revoke the access_token")
}

// TestHandleRevoke_ClientSecretPost verifies client_secret_post auth works for revoke.
func TestHandleRevoke_ClientSecretPost(t *testing.T) {
	testutils.WithTestDB(t)
	setupRevokeClient(t)

	form := url.Values{}
	form.Set("token", "some-unknown-token")
	form.Set("client_id", revokeClientID)
	form.Set("client_secret", revokeClientSecret)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	token.HandleRevoke(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

// ---------------------------------------------------------------------------
// RFC 7009 §2.1 — Cross-client token isolation
// ---------------------------------------------------------------------------

const otherRevokeClientID = "other-revoke-client"
const otherRevokeClientSecret = "other-revoke-secret"

// TestHandleRevoke_CrossClient_NoOp verifies RFC 7009 §2.1:
// "The authorization server ... verifies whether the token was issued to the
// client making the revocation request."
// A different client's revoke request returns 200 but does NOT revoke the token.
func TestHandleRevoke_CrossClient_NoOp(t *testing.T) {
	testutils.WithTestDB(t)
	_, _ = user.CreateUser(testEmail, testPassword, testEmail)

	setupRevokeClient(t)
	testutils.InsertTestConfidentialClient(t, otherRevokeClientID, otherRevokeClientSecret)

	// Issue token via revokeClientID
	body := map[string]string{
		"grant_type":    "password",
		"client_id":     revokeClientID,
		"client_secret": revokeClientSecret,
		"username":      testEmail,
		"password":      testPassword,
	}
	res := testutils.MockFormRequest(t, body, http.MethodPost, "/oauth2/token", token.HandleToken)
	var tkn token.TokenResponse
	_ = json.Unmarshal(res.Body.Bytes(), &tkn)
	assert.NotEmpty(t, tkn.AccessToken)

	// Attempt to revoke using a different client
	body = map[string]string{"token": tkn.AccessToken}
	res = testutils.MockFormRequestWithBasicAuth(t, body, http.MethodPost, "/oauth2/revoke", token.HandleRevoke, otherRevokeClientID, otherRevokeClientSecret)

	// RFC 7009 §2.1: response is always 200 to avoid leaking token existence
	assert.Equal(t, http.StatusOK, res.Code)

	// Verify the token was NOT revoked
	var revokedAt *string
	err := db.GetDB().QueryRow(`SELECT revoked_at FROM tokens WHERE access_token = ?`, tkn.AccessToken).Scan(&revokedAt)
	assert.NoError(t, err)
	assert.Nil(t, revokedAt, "RFC 7009 §2.1: cross-client revoke must be a no-op")
}
