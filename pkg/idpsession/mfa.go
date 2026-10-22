package idpsession

import (
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/user"
)

// SatisfiesMfa checks evidence from the completed login against current local
// policy. Enrollment alone is not proof that this session completed MFA.
func SatisfiesMfa(method string, usr *user.User, cfg *config.Config) bool {
	// OIDC Core §3.1.2.3: a deactivated user cannot authenticate through SSO.
	if usr == nil || usr.DeactivatedAt != nil {
		return false
	}
	if !cfg.RequireMfa && !usr.TotpVerified {
		return true
	}
	// A completed trusted-device login remains an authenticated SSO session,
	// independent of whether another client permits direct device-cookie bypass.
	if method == "trusted_device" {
		return true
	}
	if !cfg.RequireMfa {
		return method == "totp" && usr.TotpVerified
	}
	switch cfg.MfaMethod {
	case "totp":
		return method == "totp" && usr.TotpVerified
	case "email", "both":
		return method == "email" || method == "totp" && usr.TotpVerified
	default:
		return false
	}
}
