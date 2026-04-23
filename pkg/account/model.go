package account

import (
	"time"
)

type MfaStatusResponse struct {
	TotpEnabled bool `json:"totp_enabled"`
}

type TotpSetupResponse struct {
	Secret     string `json:"secret"`
	QrCodeData string `json:"qr_code_data"`
}

type TotpVerifyRequest struct {
	Code string `json:"code"`
}

type UpdatePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

type PasskeyResponse struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// SessionResponse is the account-UI view of an IdP (SSO) session — i.e. one
// browser/device. ActiveAppsCount is the number of non-deactivated OAuth
// sessions born from this IdP session (one per app signed in via SSO on this
// device). IsCurrent marks the row matching the request's IdP session cookie.
type SessionResponse struct {
	ID              string    `json:"id"`
	UserAgent       string    `json:"user_agent"`
	IPAddress       string    `json:"ip_address"`
	LastActivityAt  time.Time `json:"last_activity_at"`
	CreatedAt       time.Time `json:"created_at"`
	ActiveAppsCount int       `json:"active_apps_count"`
	IsCurrent       bool      `json:"is_current"`
}

type DisableMfaRequest struct {
	CurrentPassword string `json:"current_password"`
	Code            string `json:"code"`
}

type PasskeyRenameRequest struct {
	Name string `json:"name"`
}

type TrustedDeviceResponse struct {
	ID         string    `json:"id"`
	DeviceName string    `json:"device_name"`
	CreatedAt  time.Time `json:"created_at"`
	LastUsedAt time.Time `json:"last_used_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type ConnectedProviderResponse struct {
	ID           string    `json:"id"`
	ProviderID   string    `json:"provider_id"`
	ProviderName string    `json:"provider_name"`
	Email        string    `json:"email,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}
