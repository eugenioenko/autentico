package mfa

import "time"

type MfaChallenge struct {
	ID         string
	UserID     string
	Method     string
	Code       string
	LoginState string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	Used       bool
}

type LoginState struct {
	Redirect            string `json:"redirect"`
	State               string `json:"state"`
	ClientID            string `json:"client_id"`
	Scope               string `json:"scope"`
	Nonce               string `json:"nonce"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}
