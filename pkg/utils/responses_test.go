package utils

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eugenioenko/autentico/pkg/model"
	"github.com/stretchr/testify/assert"
)

func TestSuccessResponse(t *testing.T) {
	rr := httptest.NewRecorder()
	data := map[string]string{"message": "success"}

	SuccessResponse(rr, data)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

	var response model.ApiResponse[map[string]string]
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "success", response.Data["message"])
}

func TestSuccessResponseWithCustomStatusCode(t *testing.T) {
	rr := httptest.NewRecorder()
	data := map[string]string{"created": "true"}

	SuccessResponse(rr, data, http.StatusCreated)

	assert.Equal(t, http.StatusCreated, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
}

func TestErrorResponse(t *testing.T) {
	rr := httptest.NewRecorder()

	ErrorResponse(rr, "Something went wrong", http.StatusBadRequest)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

	var response model.ApiResponse[any]
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.NotNil(t, response.Error)
	assert.Equal(t, "Something went wrong", response.Error.Message)
	assert.Equal(t, http.StatusBadRequest, response.Error.Code)
}

func TestErrorResponseWithCustomErrorCode(t *testing.T) {
	rr := httptest.NewRecorder()

	ErrorResponse(rr, "Custom error", http.StatusBadRequest, 1001)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var response model.ApiResponse[any]
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, 1001, response.Error.Code)
}

func TestWriteApiResponse(t *testing.T) {
	rr := httptest.NewRecorder()
	data := map[string]string{"key": "value"}

	WriteApiResponse(rr, data, http.StatusOK)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

	var response map[string]string
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "value", response["key"])
}

func TestWriteErrorResponse(t *testing.T) {
	rr := httptest.NewRecorder()

	WriteErrorResponse(rr, http.StatusUnauthorized, "invalid_token", "Token has expired")

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

	var response model.AuthErrorResponse
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "invalid_token", response.Error)
	assert.Equal(t, "Token has expired", response.ErrorDescription)
}

func TestDummyRoute(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/dummy", nil)
	rr := httptest.NewRecorder()

	DummyRoute(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

	var response model.AuthErrorResponse
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "not_implemented", response.Error)
	assert.Equal(t, "Not implemented", response.ErrorDescription)
}
