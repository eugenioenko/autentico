package wellknown

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHandleWellKnownConfig(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rr := httptest.NewRecorder()

	HandleWellKnownConfig(rr, req)

	// Verify the response
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "authorization_endpoint")
	assert.Contains(t, rr.Body.String(), "token_endpoint")
	assert.Contains(t, rr.Body.String(), "userinfo_endpoint")
}
