package auth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eugenioenko/autentico/pkg/authorize"
	testutils "github.com/eugenioenko/autentico/tests/utils"

	"github.com/stretchr/testify/assert"
)

func TestAuthorizeRequest(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "test-client", []string{"https://client.example.com/callback"})

	url := `/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=https://client.example.com/callback&scope=openid`
	res := testutils.MockJSONRequest(t, "", http.MethodGet, url, authorize.HandleAuthorize)
	doc := string(res)

	assert.Contains(t, doc, "https://client.example.com/callback")
	assert.Contains(t, doc, "<body id=\"autentico\">")

}

func TestAuthorizeInvalidRequest(t *testing.T) {
	// Missing redirect_uri — cannot redirect back, shows HTML error page
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize", nil)
	authorize.HandleAuthorize(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid redirect_uri")
}
