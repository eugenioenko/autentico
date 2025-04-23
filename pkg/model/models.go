package model

import (
	"time"
)

type AuthResponse struct {
	UserID       string
	AccessToken  string
	RefreshToken string
	SessionID    string
}

type AuthToken struct {
	UserID           string
	AccessToken      string
	RefreshToken     string
	SessionID        string
	AccessExpiresAt  time.Time
	RefreshExpiresAt time.Time
}

type ApiError struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
}

type ApiResponse[T any] struct {
	Data  T         `json:"data,omitempty"`
	Error *ApiError `json:"error,omitempty"`
}

type RevokeRequest struct {
	Token         string `json:"token"`
	TokenTypeHint string `json:"token_type_hint,omitempty"`
	ClientID      string `json:"client_id"`
	ClientSecret  string `json:"client_secret"`
}

type AuthCodeRequest struct {
	ResponseType string `json:"response_type"`
	ClientID     string `json:"client_id"`
	RedirectURI  string `json:"redirect_uri"`
	Scope        string `json:"scope"`
	State        string `json:"state"`
}

type AuthErrorResponse struct {
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}
