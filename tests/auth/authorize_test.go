package auth_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/eugenioenko/autentico/pkg/authorize"
	testutils "github.com/eugenioenko/autentico/tests/utils"

	"github.com/stretchr/testify/assert"
)

func TestAuthorizeRequest(t *testing.T) {
	url := `/oauth2/authorize?response_type=code&redirect_uri=https://client.example.com/callback&scope=openid`
	res := testutils.MockJSONRequest(t, "", http.MethodGet, url, authorize.HandleAuthorize)
	doc := string(res)

	assert.Contains(t, doc, "https://client.example.com/callback")
	assert.Contains(t, doc, "<body id=\"autentico\">")

}

func TestAuthorizeInvalidRequest(t *testing.T) {
	res := testutils.MockJSONRequest(t, "", http.MethodGet, "/oauth2/authorize", authorize.HandleAuthorize)

	var res2 map[string]interface{}
	err := json.Unmarshal(res, &res2)
	assert.NoError(t, err)
	assert.Contains(t, res2, "error")
	assert.Equal(t, "invalid_request", res2["error"])
}
