package authorize

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHandleAuthorize(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost/callback&state=xyz123", nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	// Verify the response
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "form")
	assert.Contains(t, rr.Body.String(), "username")
	assert.Contains(t, rr.Body.String(), "password")
}
