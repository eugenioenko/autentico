package authcode

import (
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"

	"github.com/stretchr/testify/assert"
)

func TestCreateAuthCode(t *testing.T) {
	testutils.WithTestDB(t)

	authCode := AuthCode{
		Code:        "test-code",
		UserID:      "user-1",
		RedirectURI: "http://localhost/callback",
		Scope:       "read",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
		Used:        false,
		CreatedAt:   time.Now(),
	}

	err := CreateAuthCode(authCode)
	assert.NoError(t, err)

	// Verify the auth code exists in the database
	var code string
	err = db.GetDB().QueryRow(`SELECT code FROM auth_codes WHERE code = 'test-code'`).Scan(&code)
	assert.NoError(t, err)
	assert.Equal(t, "test-code", code)
}

func TestCreateAuthCode_DuplicateCode(t *testing.T) {
	testutils.WithTestDB(t)

	authCode := AuthCode{
		Code:        "duplicate-code",
		UserID:      "user-1",
		ClientID:    "client-1",
		RedirectURI: "http://localhost/callback",
		Scope:       "read",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
		Used:        false,
		CreatedAt:   time.Now(),
	}

	err := CreateAuthCode(authCode)
	assert.NoError(t, err)

	// Try to insert the same code again
	err = CreateAuthCode(authCode)
	assert.Error(t, err, "Expected error when inserting duplicate auth code")
}
