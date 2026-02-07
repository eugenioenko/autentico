package idpsession

import "time"

type IdpSession struct {
	ID             string
	UserID         string
	UserAgent      string
	IPAddress      string
	LastActivityAt time.Time
	CreatedAt      time.Time
	DeactivatedAt  *time.Time
}
