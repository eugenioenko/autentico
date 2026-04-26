package verifico

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestHandleVerify_ValidMatch(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("correct"), bcrypt.MinCost)
	body, _ := json.Marshal(VerifyRequest{Hash: string(hash), Password: "correct", Secret: "test-secret"})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/verify", bytes.NewReader(body))
	HandleVerify("test-secret")(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp VerifyResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.True(t, resp.Match)
}

func TestHandleVerify_ValidMismatch(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("correct"), bcrypt.MinCost)
	body, _ := json.Marshal(VerifyRequest{Hash: string(hash), Password: "wrong", Secret: "test-secret"})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/verify", bytes.NewReader(body))
	HandleVerify("test-secret")(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp VerifyResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.False(t, resp.Match)
}

func TestHandleVerify_BadSecret(t *testing.T) {
	body, _ := json.Marshal(VerifyRequest{Hash: "x", Password: "x", Secret: "wrong"})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/verify", bytes.NewReader(body))
	HandleVerify("test-secret")(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestHandleVerify_MalformedJSON(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/verify", bytes.NewReader([]byte("not json")))
	HandleVerify("test-secret")(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleVerify_MethodNotAllowed(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/verify", nil)
	HandleVerify("test-secret")(rr, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}

func TestHandlePing_ValidSecret(t *testing.T) {
	body, _ := json.Marshal(PingRequest{Secret: "test-secret"})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/ping", bytes.NewReader(body))
	HandlePing("test-secret")(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHandlePing_BadSecret(t *testing.T) {
	body, _ := json.Marshal(PingRequest{Secret: "wrong"})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/ping", bytes.NewReader(body))
	HandlePing("test-secret")(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestHandlePing_MethodNotAllowed(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	HandlePing("test-secret")(rr, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}
