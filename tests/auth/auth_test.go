package auth_test

import (
	"autentico/pkg/auth"
	"autentico/pkg/model"
	"autentico/pkg/routes"
	"autentico/pkg/user"
	testutils "autentico/tests/utils"
	"fmt"

	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoginWithCredentials(t *testing.T) {
	testutils.WithTestDB(t)
	user.CreateUser("johndoe@mail.com", "password", "johndoe@mail.com")
	_, err := auth.LoginUser("johndoe@mail.com", "password")
	if err != nil {
		t.Fail()
	}
}

func TestIntrospect(t *testing.T) {
	email := "johndoe@mail.com"
	password := "test1234"
	testutils.WithTestDB(t)

	// create user
	body := fmt.Sprintf(`{
		"username": "%s",
		"email": "%s",
		"password": "%s"
	}`, email, email, password)

	res := testutils.MockApiRequest(t, body, http.MethodPost, "/user/create", routes.CreateUser)
	var user model.ApiUserResponse
	err := json.Unmarshal(res, &user)
	assert.NoError(t, err)
	assert.Equal(t, user.Data.Username, email)
	assert.Equal(t, user.Data.Email, email)

	// login user
	body = fmt.Sprintf(`{
			"username": "%s",
			"password": "%s"
		}`, email, password)

	res = testutils.MockApiRequest(t, body, http.MethodPost, "/users/login", routes.CreateUser)
	var token model.TokenResponse
	err = json.Unmarshal(res, &token)
	assert.NoError(t, err)
}
