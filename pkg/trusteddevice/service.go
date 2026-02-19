package trusteddevice

import (
	"net/http"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
)

const CookieName = "autentico_trusted_device"

// SetCookie writes the trusted device cookie with the given token and expiry.
func SetCookie(w http.ResponseWriter, deviceID string, expiry time.Duration) {
	cfg := config.Get()
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    deviceID,
		Path:     cfg.AppOAuthPath,
		HttpOnly: true,
		Secure:   cfg.AuthIdpSessionSecureCookie,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(expiry.Seconds()),
	})
}

// ReadCookie returns the trusted device token from the request, or "" if absent.
func ReadCookie(r *http.Request) string {
	cookie, err := r.Cookie(CookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// IsDeviceTrusted returns true if the request carries a valid, non-expired trusted
// device token that belongs to the given user.
func IsDeviceTrusted(userID string, r *http.Request) bool {
	token := ReadCookie(r)
	if token == "" {
		return false
	}
	device, err := TrustedDeviceByID(token)
	if err != nil {
		return false
	}
	if device.UserID != userID {
		return false
	}
	if time.Now().After(device.ExpiresAt) {
		return false
	}
	_ = UpdateLastUsed(token)
	return true
}
