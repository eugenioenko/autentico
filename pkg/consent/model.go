package consent

import (
	"strings"
	"time"
)

type UserConsent struct {
	ID        string    `db:"id"`
	UserID    string    `db:"user_id"`
	ClientID  string    `db:"client_id"`
	Scopes    string    `db:"scopes"`
	GrantedAt time.Time `db:"granted_at"`
}

type ScopeInfo struct {
	Name        string
	Description string
}

var scopeDescriptions = map[string]string{
	"openid":         "Verify your identity",
	"profile":        "View your profile information",
	"email":          "View your email address",
	"address":        "View your address",
	"phone":          "View your phone number",
	"offline_access": "Maintain access when you're not using the app",
}

func DescribeScopes(scopeStr string) []ScopeInfo {
	scopes := strings.Fields(scopeStr)
	result := make([]ScopeInfo, 0, len(scopes))
	for _, s := range scopes {
		desc, ok := scopeDescriptions[s]
		if !ok {
			desc = s
		}
		result = append(result, ScopeInfo{Name: s, Description: desc})
	}
	return result
}

// NeedsConsent returns true if the user must be shown a consent screen.
// OIDC Core §3.1.2.4: AS MUST obtain consent before releasing info; MAY skip if previously obtained.
func NeedsConsent(consentRequired *bool, userID, clientID, requestedScopes, prompt string) bool {
	if consentRequired == nil || !*consentRequired {
		return false
	}
	// OIDC Core §3.1.2.1: prompt=consent MUST re-prompt even if consent was previously granted
	if containsPromptValue(prompt, "consent") {
		return true
	}
	existing, err := GetConsent(userID, clientID)
	if err != nil || existing == nil {
		return true
	}
	return !scopesCovered(existing.Scopes, requestedScopes)
}

func containsPromptValue(prompt, value string) bool {
	for _, v := range strings.Fields(prompt) {
		if v == value {
			return true
		}
	}
	return false
}

func scopesCovered(grantedScopes, requestedScopes string) bool {
	granted := make(map[string]bool)
	for _, s := range strings.Fields(grantedScopes) {
		granted[s] = true
	}
	for _, s := range strings.Fields(requestedScopes) {
		if !granted[s] {
			return false
		}
	}
	return true
}
