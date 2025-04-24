package model

type ApiError struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
}

type ApiResponse[T any] struct {
	Data  T         `json:"data,omitempty"`
	Error *ApiError `json:"error,omitempty"`
}

type AuthErrorResponse struct {
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}
