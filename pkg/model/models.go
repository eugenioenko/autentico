package model

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
	Data  *UserResponse `json:"data,omitempty"`
	Error *ApiError     `json:"error,omitempty"`
}

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

// todo use this models

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope"`
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

type TokenRequest struct {
	GrantType    string `json:"grant_type"`
	Code         string `json:"code"`
	RedirectURI  string `json:"redirect_uri"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type RefreshTokenRequest struct {
	GrantType    string `json:"grant_type"`
	RefreshToken string `json:"refresh_token"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type AuthErrorResponse struct {
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}
