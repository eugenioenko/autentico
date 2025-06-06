package utils

import (
	"encoding/json"
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

func WriteErrorResponse(w http.ResponseWriter, statusCode int, errorType, errorDescription string) {
	WriteApiResponse(w, model.AuthErrorResponse{
		Error:            errorType,
		ErrorDescription: errorDescription,
	}, statusCode)
}
