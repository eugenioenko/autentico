package auth_test

import (
	"autentico/pkg/auth"
	"autentico/pkg/user"
	testutils "autentico/tests/utils"
	"testing"
)

func TestLoginWithCredentials(t *testing.T) {
	testutils.WithTestDB(t)
	user.CreateUser("johndoe@mail.com", "password", "johndoe@mail.com")
	_, err := auth.LoginUser("johndoe@mail.com", "password")
	if err != nil {
		t.Fail()
	}
}
