package trusteddevice

import "time"

type TrustedDevice struct {
	ID         string // public management ID, separate from the cookie credential
	UserID     string
	DeviceName string
	CreatedAt  time.Time
	LastUsedAt time.Time
	ExpiresAt  time.Time
}
