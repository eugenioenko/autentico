package models

import (
	"time"
)

type User struct {
	ID        string
	Username  string
	Password  string
	Email     string
	CreatedAt time.Time
}

type UserResponse struct {
	ID        string
	Username  string
	Email     string
	CreatedAt time.Time
}

// ApiUserResponse is used for Swagger documentation
type ApiUserResponse struct {
	Data  UserResponse `json:"data"`
	Error ApiError     `json:"error,omitempty"`
}

type AuthUser struct {
	ID    string `json:"id"`
	Token string `json:"token"`
}

type ApiError struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
}

type ApiResponse[T any] struct {
	Data  T         `json:"data,omitempty"`
	Error *ApiError `json:"error,omitempty"`
}
