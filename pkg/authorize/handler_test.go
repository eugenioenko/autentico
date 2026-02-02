package authorize

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
)

func TestHandleAuthorize(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost/callback&state=xyz123", nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	// Verify the response
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "form")
	assert.Contains(t, rr.Body.String(), "username")
	assert.Contains(t, rr.Body.String(), "password")
}

func TestHandleAuthorize_MissingResponseType(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?client_id=test-client&redirect_uri=http://localhost/callback&state=xyz123", nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_request")
}

func TestHandleAuthorize_InvalidResponseType(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=token&client_id=test-client&redirect_uri=http://localhost/callback&state=xyz123", nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_request")
}

func TestHandleAuthorize_InvalidRedirectURI(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=not-a-valid-uri&state=xyz123", nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_request")
}

func TestHandleAuthorize_InactiveClient(t *testing.T) {
	testutils.WithTestDB(t)

	// Insert an inactive client
	_, err := db.GetDB().Exec(`
		INSERT INTO clients (id, client_id, client_name, client_type, redirect_uris, is_active)
		VALUES ('id-1', 'inactive-client', 'Test Client', 'public', '["http://localhost/callback"]', FALSE)
	`)
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=inactive-client&redirect_uri=http://localhost/callback&state=xyz123", nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_client")
}

func TestHandleAuthorize_RedirectURINotAllowed(t *testing.T) {
	testutils.WithTestDB(t)

	// Insert a client with specific allowed redirect URIs
	_, err := db.GetDB().Exec(`
		INSERT INTO clients (id, client_id, client_name, client_type, redirect_uris, is_active)
		VALUES ('id-2', 'strict-client', 'Test Client', 'confidential', '["http://allowed.com/callback"]', TRUE)
	`)
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=strict-client&redirect_uri=http://notallowed.com/callback&state=xyz123", nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Redirect URI not allowed")
}

func TestHandleAuthorize_ResponseTypeNotAllowed(t *testing.T) {
	testutils.WithTestDB(t)

	// Insert a client with only token response type allowed
	_, err := db.GetDB().Exec(`
		INSERT INTO clients (id, client_id, client_name, client_type, redirect_uris, response_types, is_active)
		VALUES ('id-3', 'token-only-client', 'Test Client', 'public', '["http://localhost/callback"]', '["token"]', TRUE)
	`)
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=token-only-client&redirect_uri=http://localhost/callback&state=xyz123", nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "unsupported_response_type")
}
