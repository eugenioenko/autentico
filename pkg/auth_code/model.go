package authcode

import "time"

type AuthCode struct {
	Code        string
	UserID      string
	RedirectURI string
	Scope       string
	ExpiresAt   time.Time
	Used        bool
	CreatedAt   time.Time
}
