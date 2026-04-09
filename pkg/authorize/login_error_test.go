package authorize

import (
	"net/http"
	"net/http/httptest"
	"testing"

	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
)

func TestHandleAuthorize_WithLoginError(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "c1", []string{"http://localhost/cb"})

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=c1&redirect_uri=http://localhost/cb&error=invalid_credentials&code_challenge=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk&code_challenge_method=S256", nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	// Error is passed through to the login redirect
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Contains(t, rr.Header().Get("Location"), "invalid_credentials")
}
