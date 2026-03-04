package authorize

import (
	"net/http"
	"net/http/httptest"
	"testing"

	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
)

func TestHandleAuthorize_WithErrorDescription(t *testing.T) {
	testutils.WithTestDB(t)
	
	// Trigger renderError with a validation error (missing fields)
	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?error=invalid_request", nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	// Implementation returns 403 on validation error
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "RedirectURI: cannot be blank")
}
