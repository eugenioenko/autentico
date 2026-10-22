package client

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseMaxAge returns the requested nonnegative age in seconds, or -1 when it
// is absent. Invalid and overflowing values cannot silently disable freshness.
func ParseMaxAge(raw string) (int64, error) {
	if raw == "" {
		return -1, nil
	}
	// OIDC Core §3.1.2.1: max_age is a nonnegative number of seconds.
	for _, ch := range raw {
		if ch < '0' || ch > '9' {
			return -1, fmt.Errorf("max_age must be a nonnegative integer")
		}
	}
	seconds, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return -1, fmt.Errorf("max_age is out of range")
	}
	return seconds, nil
}

// HasPrompt matches complete OIDC prompt values rather than substrings.
func HasPrompt(prompt, wanted string) bool {
	for _, value := range strings.Fields(prompt) {
		if value == wanted {
			return true
		}
	}
	return false
}

// LoginPrompt keeps authentication/consent controls when returning from signup
// or recovery, without reopening the account-creation screen in a loop.
func LoginPrompt(prompt string) string {
	values := make([]string, 0)
	create := HasPrompt(prompt, "create")
	for _, value := range strings.Fields(prompt) {
		if value != "create" {
			values = append(values, value)
		}
	}
	if create && !HasPrompt(prompt, "login") && !HasPrompt(prompt, "none") {
		values = append(values, "login")
	}
	return strings.Join(values, " ")
}

// ValidatePrompt enforces the non-interactive prompt's exclusive use.
func ValidatePrompt(prompt string) error {
	// OIDC Core §3.1.2.1: none must not be combined with any other prompt.
	if HasPrompt(prompt, "none") && len(strings.Fields(prompt)) != 1 {
		return fmt.Errorf("prompt=none cannot be combined with other prompts")
	}
	return nil
}
