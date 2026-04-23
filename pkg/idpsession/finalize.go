package idpsession

import (
	"net/http"

	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/utils"
)

func FinalizeLogin(w http.ResponseWriter, r *http.Request, userID string) string {
	sessionID, err := authcode.GenerateSecureCode()
	if err != nil {
		return ""
	}
	session := IdpSession{
		ID:        sessionID,
		UserID:    userID,
		UserAgent: r.UserAgent(),
		IPAddress: utils.GetClientIP(r),
	}
	if CreateIdpSession(session) != nil {
		return ""
	}
	SetCookie(w, sessionID)
	return sessionID
}
