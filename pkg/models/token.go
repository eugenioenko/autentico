package models

import "time"

type Token struct {
	ID                     string
	UserID                 string
	AccessToken            string
	RefreshToken           string
	AccessTokenType        string
	RefreshTokenExpiresAt  time.Time
	RefreshTokenLastUsedAt time.Time
	AccessTokenExpiresAt   time.Time
	IssuedAt               time.Time
	Scope                  string
	GrantType              string
	RevokedAt              time.Time
}
