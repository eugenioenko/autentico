package models

import "time"

type Session struct {
	ID             string
	UserID         string
	AccessToken    string
	RefreshToken   string
	UserAgent      string
	IPAddress      string
	DeviceID       string
	LastActivityAt time.Time
	CreatedAt      time.Time
	ExpiresAt      time.Time
	DeactivatedAt  *time.Time
	Location       string
}
