package token_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/token"
	"github.com/eugenioenko/autentico/pkg/user"
	testutils "github.com/eugenioenko/autentico/tests/utils"

	"github.com/stretchr/testify/assert"
)

const (
	testEmail    = "johndoe@mail.com"
	testPassword = "password"
)

// TestHandleRevoke_InvalidToken_Returns200 verifies RFC 7009 §2.2:
// "The authorization server responds with HTTP status code 200 if the token
// has been revoked successfully or if the client submitted an invalid token."
// "Note: invalid tokens do not cause an error response."
func TestHandleRevoke_InvalidToken_Returns200(t *testing.T) {
	testutils.WithTestDB(t)

	body := map[string]string{"token": "this-is-not-a-valid-jwt"}
	res := testutils.MockFormRequest(t, body, http.MethodPost, "/oauth2/revoke", token.HandleRevoke)

	assert.Equal(t, http.StatusOK, res.Code, "RFC 7009 §2.2: invalid token MUST return 200, not 4xx")
}

// TestHandleRevoke_UnknownToken_Returns200 verifies RFC 7009 §2.2 for a
// well-formed but unrecognised token (e.g. issued by a different server).
func TestHandleRevoke_UnknownToken_Returns200(t *testing.T) {
	testutils.WithTestDB(t)

	// A syntactically valid JWT that won't validate (wrong signature)
	fakeJWT := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1bmtub3duIiwiZXhwIjo5OTk5OTk5OTk5fQ.invalidsignature"
	body := map[string]string{"token": fakeJWT}
	res := testutils.MockFormRequest(t, body, http.MethodPost, "/oauth2/revoke", token.HandleRevoke)

	assert.Equal(t, http.StatusOK, res.Code, "RFC 7009 §2.2: unrecognised token MUST return 200, not 4xx")
}

func TestHandleRevoke(t *testing.T) {
	testutils.WithTestDB(t)
	_, _ = user.CreateUser(testEmail, testPassword, testEmail)

	_, err := db.GetDB().Exec(`
		INSERT INTO clients (id, client_id, client_name, client_type, redirect_uris, grant_types, is_active)
		VALUES ('revoke-test-id', 'revoke-test-client', 'Revoke Test Client', 'public', '[]', '["password","refresh_token"]', TRUE)
	`)
	if err != nil {
		t.Fatalf("failed to insert test client: %v", err)
	}

	body := map[string]string{
		"grant_type": "password",
		"client_id":  "revoke-test-client",
		"username":   testEmail,
		"password":   testPassword,
	}
	res := testutils.MockFormRequest(t, body, http.MethodPost, "/oauth2/token", token.HandleToken)

	var tkn token.TokenResponse
	_ = json.Unmarshal(res.Body.Bytes(), &tkn)

	// Revoke the token
	body = map[string]string{
		"token": tkn.AccessToken,
	}
	res = testutils.MockFormRequest(t, body, http.MethodPost, "/oauth2/revoke", token.HandleRevoke)

	// Verify the response
	assert.Equal(t, http.StatusOK, res.Code)

	// Verify the token is revoked
	var revokedAt string
	err = db.GetDB().QueryRow(fmt.Sprintf(`SELECT revoked_at FROM tokens WHERE access_token = '%s'`, tkn.AccessToken)).Scan(&revokedAt)
	assert.NoError(t, err)
	assert.NotEmpty(t, revokedAt)
}

// RFC 7009 §2.1: token_type_hint is OPTIONAL; the server MAY ignore it.
// §2.2: an invalid token_type_hint value is ignored and does not influence the response.
func TestHandleRevoke_TokenTypeHint_Accepted(t *testing.T) {
	testutils.WithTestDB(t)

	body := map[string]string{
		"token":           "nonexistent-token",
		"token_type_hint": "refresh_token",
	}
	res := testutils.MockFormRequest(t, body, http.MethodPost, "/oauth2/revoke", token.HandleRevoke)
	assert.Equal(t, http.StatusOK, res.Code, "RFC 7009 §2.1: token_type_hint must be accepted without error")
}

// RFC 7009 §2.2: invalid token_type_hint is ignored
func TestHandleRevoke_InvalidTokenTypeHint_Ignored(t *testing.T) {
	testutils.WithTestDB(t)

	body := map[string]string{
		"token":           "nonexistent-token",
		"token_type_hint": "totally_invalid_hint",
	}
	res := testutils.MockFormRequest(t, body, http.MethodPost, "/oauth2/revoke", token.HandleRevoke)
	assert.Equal(t, http.StatusOK, res.Code, "RFC 7009 §2.2: invalid hint must be ignored, still return 200")
}

// RFC 7009 §2.2: revoking a refresh token SHOULD also invalidate the access token
// on the same authorization grant. Our schema stores both on the same row.
func TestHandleRevoke_RefreshToken_AlsoRevokesAccess(t *testing.T) {
	testutils.WithTestDB(t)
	_, _ = user.CreateUser(testEmail, testPassword, testEmail)

	_, err := db.GetDB().Exec(`
		INSERT INTO clients (id, client_id, client_name, client_type, redirect_uris, grant_types, is_active)
		VALUES ('revoke-refresh-id', 'revoke-refresh-client', 'Revoke Refresh Client', 'public', '[]', '["password","refresh_token"]', TRUE)
	`)
	assert.NoError(t, err)

	body := map[string]string{
		"grant_type": "password",
		"client_id":  "revoke-refresh-client",
		"username":   testEmail,
		"password":   testPassword,
	}
	res := testutils.MockFormRequest(t, body, http.MethodPost, "/oauth2/token", token.HandleToken)

	var tkn token.TokenResponse
	_ = json.Unmarshal(res.Body.Bytes(), &tkn)
	assert.NotEmpty(t, tkn.RefreshToken)
	assert.NotEmpty(t, tkn.AccessToken)

	// Revoke by refresh_token
	body = map[string]string{"token": tkn.RefreshToken}
	res = testutils.MockFormRequest(t, body, http.MethodPost, "/oauth2/revoke", token.HandleRevoke)
	assert.Equal(t, http.StatusOK, res.Code)

	// Both tokens on the same row should now be revoked
	var revokedAt string
	err = db.GetDB().QueryRow(`SELECT revoked_at FROM tokens WHERE access_token = ?`, tkn.AccessToken).Scan(&revokedAt)
	assert.NoError(t, err)
	assert.NotEmpty(t, revokedAt, "RFC 7009 §2.2: revoking refresh_token must also revoke the access_token")
}
