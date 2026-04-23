package authcode

import "time"

type AuthCode struct {
	Code                string
	UserID              string
	ClientID            string
	RedirectURI         string
	Scope               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
	Used                bool
	CreatedAt           time.Time
	// IdpSessionID links the authorization code to the IdP (SSO) session that
	// authenticated the end-user at /authorize. Nullable: empty for flows that
	// don't go through a browser session (ROPC, client_credentials). Carried
	// forward to sessions.idp_session_id at code exchange so DeactivateWithCascade
	// can revoke every OAuth session born from a single browser login.
	IdpSessionID string
}
