package session

import "time"

type Session struct {
	ID             string
	UserID         string
	AccessToken    string
	RefreshToken   string
	UserAgent      string
	IPAddress      string
	DeviceID       *string
	LastActivityAt *time.Time
	CreatedAt      time.Time
	ExpiresAt      time.Time
	DeactivatedAt  *time.Time
	Location       string
}

// SessionResponse is the admin-safe representation (no tokens)
type SessionResponse struct {
	ID             string     `json:"id"`
	UserID         string     `json:"user_id"`
	UserAgent      string     `json:"user_agent"`
	IPAddress      string     `json:"ip_address"`
	DeviceID       *string    `json:"device_id"`
	LastActivityAt *time.Time `json:"last_activity_at"`
	CreatedAt      time.Time  `json:"created_at"`
	ExpiresAt      time.Time  `json:"expires_at"`
	DeactivatedAt  *time.Time `json:"deactivated_at"`
	Location       string     `json:"location"`
	Status         string     `json:"status"`
}

func (s *Session) ToResponse() SessionResponse {
	status := "active"
	if s.DeactivatedAt != nil {
		status = "deactivated"
	} else if time.Now().After(s.ExpiresAt) {
		status = "expired"
	}
	return SessionResponse{
		ID:             s.ID,
		UserID:         s.UserID,
		UserAgent:      s.UserAgent,
		IPAddress:      s.IPAddress,
		DeviceID:       s.DeviceID,
		LastActivityAt: s.LastActivityAt,
		CreatedAt:      s.CreatedAt,
		ExpiresAt:      s.ExpiresAt,
		DeactivatedAt:  s.DeactivatedAt,
		Location:       s.Location,
		Status:         status,
	}
}
