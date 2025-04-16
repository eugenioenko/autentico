package auth_test

import (
	"autentico/pkg/model"
	"autentico/pkg/routes"
	testutils "autentico/tests/utils"
	"encoding/json"

	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthorizeRequest(t *testing.T) {
	url := `/authorize?response_type=code&redirect_uri=https://client.example.com/callback&scope=openid`
	res := testutils.MockApiRequest(t, "", http.MethodGet, url, routes.Authorize)
	var res2 model.AuthorizeErrorResponse
	err := json.Unmarshal(res, &res2)
	assert.NoError(t, err)
	assert.Equal(t, res2.Error, "invalid_request")
}

func TestAuthorizeInvalidRequest(t *testing.T) {

	res := testutils.MockApiRequest(t, "", http.MethodGet, "/authorize", routes.Authorize)
	var res2 model.AuthorizeErrorResponse
	err := json.Unmarshal(res, &res2)
	assert.NoError(t, err)
	assert.Equal(t, res2.Error, "invalid_request")
}
