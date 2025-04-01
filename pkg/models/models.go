package models

import "time"

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

type AuthUser struct {
	ID    string `json:"id"`
	Token string `json:"token"`
}

type ApiError struct {
	Message string `json:"error"`
	Code    int    `json:"code"`
}

type ApiResponse struct {
	Data  any       `json:"data,omitempty"`
	Error *ApiError `json:"error,omitempty"`
}
