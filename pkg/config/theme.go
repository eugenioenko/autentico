package config

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
)

var dataImageURLPattern = regexp.MustCompile(`^data:image/(png|jpeg|gif|webp|svg\+xml)[;,]`)

// ValidateLogoURL accepts an empty value, a same-origin path, a data:image URI,
// an https URL, or an absolute URL on the app's own origin.
func ValidateLogoURL(raw string) error {
	if raw == "" {
		return nil
	}
	if dataImageURLPattern.MatchString(raw) {
		return nil
	}
	if strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") && !strings.HasPrefix(raw, "/\\") {
		if _, err := url.Parse(raw); err != nil {
			return errors.New("logo URL is not a valid path")
		}
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || strings.ContainsAny(u.Host, " ;,'\"") {
		return errors.New("logo URL must be an https URL, a path starting with /, or a data:image URI")
	}
	if u.Scheme == "https" || isAppOrigin(u) {
		return nil
	}
	return errors.New("logo URL must use https")
}

// LogoOrigin returns the origin to allow in the CSP img-src directive for a
// cross-origin logo, or "" when the logo is same-origin, inline, or invalid.
func LogoOrigin(raw string) string {
	if raw == "" || ValidateLogoURL(raw) != nil || strings.HasPrefix(raw, "data:") || strings.HasPrefix(raw, "/") {
		return ""
	}
	u, _ := url.Parse(raw)
	if isAppOrigin(u) {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func isAppOrigin(u *url.URL) bool {
	app, err := url.Parse(GetBootstrap().AppURL)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Scheme, app.Scheme) && strings.EqualFold(u.Host, app.Host)
}
