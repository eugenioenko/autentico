package devicecode

import "time"

// DeviceCode represents a device authorization request in the database.
type DeviceCode struct {
	Code            string     `db:"code"`
	UserCode        string     `db:"user_code"`
	ClientID        string     `db:"client_id"`
	Scope           string     `db:"scope"`
	ExpiresAt       time.Time  `db:"expires_at"`
	IntervalSeconds int        `db:"interval_seconds"`
	UserID          *string    `db:"user_id"`
	Status          string     `db:"status"`
	LastPolledAt    *time.Time `db:"last_polled_at"`
	CreatedAt       time.Time  `db:"created_at"`
}

// RFC 8628 §3.2: Device Authorization Response
type DeviceAuthorizationResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval,omitempty"`
}
