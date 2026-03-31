package utils

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/eugenioenko/autentico/pkg/model"
)

func SuccessResponse[T any](w http.ResponseWriter, data T, statusCodes ...int) {
	statusCode := http.StatusOK
	if len(statusCodes) > 0 {
		statusCode = statusCodes[0]
	}
	apiResponse := model.ApiResponse[T]{Data: data}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(apiResponse); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

func ErrorResponse(w http.ResponseWriter, message string, statusCode int, errorCodes ...int) {
	errorCode := statusCode
	if len(errorCodes) > 0 {
		errorCode = errorCodes[0]
	}
	apiError := &model.ApiError{Message: message, Code: errorCode}
	apiResponse := model.ApiResponse[any]{Error: apiError}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(apiResponse); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

func WriteApiResponse(w http.ResponseWriter, data any, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

// WriteErrorResponse writes an OAuth2 error response.
// RFC 6749 §5.2: error responses MUST include "error" and MAY include "error_description".
// HTTP status MUST be 400 for all error codes except invalid_client, which MUST use 401.
func WriteErrorResponse(w http.ResponseWriter, statusCode int, errorType, errorDescription string) {
	WriteApiResponse(w, model.AuthErrorResponse{
		Error:            errorType,
		ErrorDescription: errorDescription,
	}, statusCode)
}

// WriteBearerUnauthorized writes a 401 response with the WWW-Authenticate header
// required by RFC 6750 §3. When errType is empty only the realm is included
// (no credentials presented); otherwise error and error_description are added.
func WriteBearerUnauthorized(w http.ResponseWriter, realm, errType, errDescription string) {
	var challenge string
	if errType == "" {
		challenge = fmt.Sprintf(`Bearer realm="%s"`, realm)
	} else {
		challenge = fmt.Sprintf(`Bearer realm="%s", error="%s", error_description="%s"`, realm, errType, errDescription)
	}
	w.Header().Set("WWW-Authenticate", challenge)
	WriteErrorResponse(w, http.StatusUnauthorized, errType, errDescription)
}
