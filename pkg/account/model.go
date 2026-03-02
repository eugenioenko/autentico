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

type SessionResponse struct {
	ID             string     `json:"id"`
	UserAgent      string     `json:"user_agent"`
	IPAddress      string     `json:"ip_address"`
	LastActivityAt *time.Time `json:"last_activity_at"`
	CreatedAt      time.Time  `json:"created_at"`
	IsCurrent      bool       `json:"is_current"`
}
