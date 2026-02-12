package authcode

import "time"

type AuthCode struct {
	Code        string
	UserID      string
	ClientID    string
	RedirectURI string
	Scope       string
	Nonce       string
	ExpiresAt   time.Time
	Used        bool
	CreatedAt   time.Time
}
