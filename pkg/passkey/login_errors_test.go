package passkey

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
)

func TestHandleLoginBegin_UserNotFound(t *testing.T) {
	testutils.WithTestDB(t)
	withPasskeyConfig(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/passkey/login/begin?username=nonexistent", nil)
	rr := httptest.NewRecorder()
	HandleLoginBegin(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	var resp map[string]string
	_ = json.NewDecoder(rr.Body).Decode(&resp)
	assert.Contains(t, resp["error"], "invalid username or passkey")
}

func TestHandleLoginBegin_NoPasskeys(t *testing.T) {
	testutils.WithTestDB(t)
	withPasskeyConfig(t)
	_, username := setupPasskeyTestUser(t) // This user has no passkeys yet

	req := httptest.NewRequest(http.MethodGet, "/oauth2/passkey/login/begin?username="+username, nil)
	rr := httptest.NewRecorder()
	HandleLoginBegin(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	var resp map[string]string
	_ = json.NewDecoder(rr.Body).Decode(&resp)
	assert.Contains(t, resp["error"], "no passkeys registered")
}

func TestHandleLoginBegin_EmptyUsername(t *testing.T) {
	testutils.WithTestDB(t)
	withPasskeyConfig(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/passkey/login/begin", nil)
	rr := httptest.NewRecorder()
	HandleLoginBegin(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}
