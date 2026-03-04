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

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=c1&redirect_uri=http://localhost/cb&error=invalid_credentials", nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_credentials")
}
