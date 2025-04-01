package utils

import (
	. "autentico/pkg/models"
	"encoding/json"
	"net/http"
)

func SuccessResponse(w http.ResponseWriter, data interface{}, statusCodes ...int) {
	statusCode := http.StatusOK
	if len(statusCodes) > 0 {
		statusCode = statusCodes[0]
	}
	apiResponse := ApiResponse{Data: data}
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
	apiError := &ApiError{Message: message, Code: errorCode}
	apiResponse := ApiResponse{Error: apiError}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(apiResponse); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}
