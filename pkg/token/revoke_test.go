package token_test

import (
	"autentico/pkg/db"
	"autentico/pkg/token"
	"autentico/pkg/user"
	testutils "autentico/tests/utils"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	testEmail    = "johndoe@mail.com"
	testPassword = "password"
)

func TestHandleRevoke(t *testing.T) {
	testutils.WithTestDB(t)
	_, _ = user.CreateUser(testEmail, testPassword, testEmail)

	body := map[string]string{
		"grant_type": "password",
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
	err := db.GetDB().QueryRow(fmt.Sprintf(`SELECT revoked_at FROM tokens WHERE access_token = '%s'`, tkn.AccessToken)).Scan(&revokedAt)
	assert.NoError(t, err)
	assert.NotEmpty(t, revokedAt)
}
