package idpsession

import (
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
)

// IsFresh applies the requesting client's idle limit and the absolute session
// age limit. Callers must separately validate the account and MFA evidence.
func IsFresh(session *IdpSession, cfg *config.Config, now time.Time) bool {
	// OIDC Core §3.1.2.3: invalid or future-dated authentication is not SSO.
	if session == nil || session.CreatedAt.IsZero() || session.LastActivityAt.IsZero() ||
		now.Before(session.CreatedAt) || now.Before(session.LastActivityAt) {
		return false
	}
	return (cfg.AuthSsoSessionIdleTimeout == 0 || now.Sub(session.LastActivityAt) < cfg.AuthSsoSessionIdleTimeout) &&
		(cfg.AuthSsoSessionMaxAge == 0 || now.Sub(session.CreatedAt) < cfg.AuthSsoSessionMaxAge)
}

// WithinMaxAge compares seconds without overflowing time.Duration for large
// max_age values. Zero always requires active authentication for this request.
func WithinMaxAge(session *IdpSession, seconds int64, now time.Time) bool {
	if session == nil || now.Before(session.CreatedAt) {
		return false
	}
	if seconds < 0 {
		return true
	}
	return seconds > 0 && now.Sub(session.CreatedAt).Seconds() <= float64(seconds)
}
