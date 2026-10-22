package idpsession

import (
	"net/http"

	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// FinalizeLogin creates a session without MFA evidence, for onboarding. Browser authentication uses the policy-gated login finalizer.
func FinalizeLogin(w http.ResponseWriter, r *http.Request, userID string) string {
	return FinalizeLoginWithMfa(w, r, userID, "")
}

// FinalizeLoginWithMfa records the local MFA decision before setting the cookie.
// Call only after completing the required authentication steps.
func FinalizeLoginWithMfa(w http.ResponseWriter, r *http.Request, userID, method string) string {
	sessionID, err := authcode.GenerateSecureCode()
	if err != nil {
		return ""
	}
	session := IdpSession{
		ID:        sessionID,
		UserID:    userID,
		UserAgent: r.UserAgent(),
		IPAddress: utils.GetClientIP(r),
		MfaMethod: method,
	}
	if CreateIdpSession(session) != nil {
		return ""
	}
	SetCookie(w, sessionID)
	return sessionID
}
