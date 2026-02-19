package passkey

import (
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/go-webauthn/webauthn/webauthn"
)

type PasskeyChallenge struct {
	ID            string
	UserID        string
	ChallengeData string // JSON-encoded webauthn.SessionData
	Type          string // "registration" or "authentication"
	LoginState    string // JSON-encoded LoginState
	CreatedAt     time.Time
	ExpiresAt     time.Time
	Used          bool
}

type PasskeyCredential struct {
	ID         string
	UserID     string
	Name       string
	Credential string // JSON-encoded webauthn.Credential
	CreatedAt  time.Time
	LastUsedAt *time.Time
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

// WebAuthnUser implements the webauthn.User interface.
type WebAuthnUser struct {
	ID          []byte
	Name        string
	Credentials []webauthn.Credential
}

func (u WebAuthnUser) WebAuthnID() []byte                         { return u.ID }
func (u WebAuthnUser) WebAuthnName() string                       { return u.Name }
func (u WebAuthnUser) WebAuthnDisplayName() string                { return u.Name }
func (u WebAuthnUser) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

// NewWebAuthn creates a WebAuthn instance from the current config.
func NewWebAuthn() (*webauthn.WebAuthn, error) {
	cfg := config.Get()
	return webauthn.New(&webauthn.Config{
		RPDisplayName: cfg.PasskeyRPName,
		RPID:          cfg.AppDomain,
		RPOrigins:     []string{cfg.AppURL},
	})
}
