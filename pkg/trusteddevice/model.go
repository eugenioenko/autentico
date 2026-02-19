package trusteddevice

import "time"

type TrustedDevice struct {
	ID         string    // token stored in cookie
	UserID     string
	DeviceName string
	CreatedAt  time.Time
	LastUsedAt time.Time
	ExpiresAt  time.Time
}
