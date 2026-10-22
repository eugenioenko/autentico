package mfa

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/eugenioenko/autentico/pkg/audit"
	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/authzsig"
	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/consent"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	"github.com/eugenioenko/autentico/pkg/trusteddevice"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// PrimaryMethod identifies the primary credential the caller has verified.
// Passkeys and upstream logins do not replace the configured local MFA step.
type PrimaryMethod string

const (
	PrimaryPassword     PrimaryMethod = "password"
	PrimarySignup       PrimaryMethod = "signup"
	PrimaryPasskey      PrimaryMethod = "passkey"
	PrimaryFederation   PrimaryMethod = "federation"
	PrimaryMagicLink    PrimaryMethod = "magic_link"
	PrimaryVerification PrimaryMethod = "email_verification"
)

// FinishLogin applies the current registration, local MFA and consent policy
// after primary authentication. It returns the next browser URL, also suitable
// for passkey JSON responses. No authenticated cookie or code precedes MFA.
func FinishLogin(w http.ResponseWriter, r *http.Request, userID string, state LoginState, primary PrimaryMethod) (string, error) {
	state.PrimaryMethod = primary
	return finishLogin(w, r, userID, state, primary, "")
}

// verifiedMethod is private: only the handler that consumes a verified MFA
// challenge can claim completion of that second factor.
func finishLogin(w http.ResponseWriter, r *http.Request, userID string, state LoginState, primary PrimaryMethod, verifiedMethod string) (string, error) {
	// RFC 6749 §4.1.1 / §10.6 / RFC 7636 §4.4.1: check the current
	// registration before issuing a challenge, session, consent or code.
	registered, err := client.ValidateAuthorization(authzsig.AuthorizeParams{
		ClientID: state.ClientID, RedirectURI: state.RedirectURI, Scope: state.Scope,
		State: state.State, Nonce: state.Nonce, CodeChallenge: state.CodeChallenge,
		CodeChallengeMethod: state.CodeChallengeMethod,
	})
	if err != nil {
		return "", err
	}
	usr, err := user.UserByID(userID)
	// OIDC Core §3.1.2.3: primary authentication cannot activate a disabled user.
	if err != nil || usr == nil || usr.DeactivatedAt != nil {
		return "", fmt.Errorf("account is unavailable")
	}
	cfg := config.GetForClient(registered.ToOverrides())
	method := verifiedMethod
	if verifiedMethod != "" {
		// OIDC Core §3.1.2.3: a policy change during the challenge must not
		// turn verification of an obsolete method into an authenticated session.
		if !idpsession.SatisfiesMfa(verifiedMethod, usr, &cfg) {
			return "", fmt.Errorf("authentication requirements changed; please log in again")
		}
	} else if cfg.RequireMfa || usr.TotpVerified {
		if cfg.TrustDeviceEnabled && trusteddevice.IsDeviceTrusted(usr.ID, r) {
			method = "trusted_device"
		} else {
			method = cfg.MfaMethod
			if !cfg.RequireMfa && usr.TotpVerified {
				method = "totp"
			} else if method == "both" {
				if usr.TotpVerified {
					method = "totp"
				} else {
					method = "email"
				}
			}
			// The existing email-login policy avoids repeating proof of email
			// ownership. It never substitutes for configured or voluntary TOTP.
			emailProven := primary == PrimaryMagicLink || primary == PrimaryVerification
			if method != "email" || !emailProven {
				if method == "email" && (cfg.SmtpHost == "" || usr.Email == "") {
					if usr.TotpVerified {
						method = "totp"
					} else {
						return "", fmt.Errorf("email verification is not available; please contact support")
					}
				}
				// RFC 4226 §7.3: unknown local policies fail closed.
				if method != "email" && method != "totp" {
					return "", fmt.Errorf("invalid MFA policy")
				}
				return startLoginChallenge(usr.ID, state, method)
			}
		}
	}

	// OIDC Core §3.1.2.3: only a completed authentication establishes SSO.
	idpSessionID := idpsession.FinalizeLoginWithMfa(w, r, usr.ID, method)
	if idpSessionID == "" {
		return "", fmt.Errorf("failed to create browser session")
	}
	details := audit.Detail("method", string(primary))
	if state.ProviderID != "" {
		details = audit.Detail("method", string(primary), "provider", state.ProviderID)
	}
	audit.Log(audit.EventLoginSuccess, usr, audit.TargetUser, usr.ID, details, utils.GetClientIP(r))
	if primary == PrimaryMagicLink {
		audit.Log(audit.EventMagicLinkLoginSuccess, usr, audit.TargetUser, usr.ID, details, utils.GetClientIP(r))
	}
	// OIDC Core §3.1.2.4: every primary method observes local client consent.
	if consent.NeedsConsent(registered.ConsentRequired, usr.ID, state.ClientID, state.Scope, state.Prompt) {
		return consent.URL(consent.ConsentParams{
			ClientID: state.ClientID, RedirectURI: state.RedirectURI, Scope: state.Scope,
			State: state.State, Nonce: state.Nonce, CodeChallenge: state.CodeChallenge,
			CodeChallengeMethod: state.CodeChallengeMethod, Prompt: state.Prompt,
		}), nil
	}
	code, err := authcode.GenerateSecureCode()
	if err != nil {
		return "", fmt.Errorf("failed to generate authorization code: %w", err)
	}
	if err := authcode.CreateAuthCode(authcode.AuthCode{
		Code: code, UserID: usr.ID, ClientID: state.ClientID, RedirectURI: state.RedirectURI,
		Scope: state.Scope, Nonce: state.Nonce, CodeChallenge: state.CodeChallenge,
		CodeChallengeMethod: state.CodeChallengeMethod, IdpSessionID: idpSessionID,
		ExpiresAt: time.Now().Add(cfg.AuthAuthorizationCodeExpiration),
	}); err != nil {
		return "", fmt.Errorf("failed to create authorization code: %w", err)
	}
	// RFC 6749 §4.1.2: retain registered queries and echo opaque state safely.
	callback, err := url.Parse(state.RedirectURI)
	if err != nil {
		return "", err
	}
	query := callback.Query()
	query.Set("code", code)
	query.Set("state", state.State)
	callback.RawQuery = query.Encode()
	return callback.String(), nil
}

// startLoginChallenge stores only server-validated authorization state.
func startLoginChallenge(userID string, state LoginState, method string) (string, error) {
	data, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	id, err := authcode.GenerateSecureCode()
	if err != nil {
		return "", err
	}
	if err := CreateMfaChallenge(MfaChallenge{
		ID: id, UserID: userID, Method: method, LoginState: string(data),
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}); err != nil {
		return "", err
	}
	// OIDC Core §3.1.2.3: continue authentication before consent or code issuance.
	return config.GetBootstrap().AppOAuthPath + "/mfa?challenge_id=" + id, nil
}
