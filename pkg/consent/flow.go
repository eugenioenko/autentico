package consent

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/idpsession"
)

const consentFlowLifetime = 10 * time.Minute

type flowKind string

const (
	flowLogin flowKind = "login"
	flowSSO   flowKind = "sso"
)

type flowClaims struct {
	Kind      flowKind `json:"kind"`
	IssuedAt  int64    `json:"iat"`
	ExpiresAt int64    `json:"exp"`
}

// LoginURL continues a just-completed active login. It binds the authorization
// request to the newly created browser session, including when SSO is disabled.
// Only the primary/MFA login finalizer may grant this fresh-login context.
func LoginURL(params ConsentParams, sessionID string) (string, error) {
	return flowURL(params, sessionID, flowLogin, time.Now())
}

// flowURL is called only after active login or eligible SSO, never from the
// public consent GET. The URL contains no browser-session credential.
func flowURL(params ConsentParams, sessionID string, kind flowKind, now time.Time) (string, error) {
	if sessionID == "" {
		return "", fmt.Errorf("authentication required")
	}
	claims := flowClaims{Kind: kind, IssuedAt: now.Unix(), ExpiresAt: now.Add(consentFlowLifetime).Unix()}
	data, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(data)
	params.FlowToken = payload + "." + signFlow(params, sessionID, payload)
	return URL(params), nil
}

// verifyFlow requires the original session and unmodified request. An old
// cookie alone cannot manufacture a continuation for a new authorization.
func verifyFlow(params ConsentParams, session *idpsession.IdpSession, now time.Time) (*flowClaims, error) {
	// RFC 6749 §10.12: authenticate the browser-bound continuation before parsing.
	if session == nil || params.FlowToken == "" || len(params.FlowToken) > 2048 {
		return nil, fmt.Errorf("invalid consent continuation")
	}
	parts := strings.Split(params.FlowToken, ".")
	if len(parts) != 2 || !hmac.Equal([]byte(parts[1]), []byte(signFlow(params, session.ID, parts[0]))) {
		return nil, fmt.Errorf("invalid consent continuation")
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid consent continuation")
	}
	var claims flowClaims
	if err := json.Unmarshal(data, &claims); err != nil {
		return nil, fmt.Errorf("invalid consent continuation")
	}
	// OIDC Core §3.1.2.3–4: a continuation is short-lived and cannot predate
	// its authentication, claim a future login, or invent an origin.
	if (claims.Kind != flowLogin && claims.Kind != flowSSO) ||
		claims.ExpiresAt <= claims.IssuedAt || claims.ExpiresAt-claims.IssuedAt > int64(consentFlowLifetime/time.Second) ||
		claims.IssuedAt > now.Unix() || session.CreatedAt.Unix() > claims.IssuedAt || now.Unix() >= claims.ExpiresAt {
		return nil, fmt.Errorf("consent continuation expired")
	}
	return &claims, nil
}

// signFlow separates continuation signatures from form and authorize signatures.
func signFlow(params ConsentParams, sessionID, payload string) string {
	values := params.values()
	values.Del("consent_flow")
	values.Set("purpose", "consent-flow-v1")
	values.Set("session_id", sessionID)
	values.Set("payload", payload)
	return signValues(values)
}

// signValues uses unambiguous form encoding, including opaque values with newlines.
func signValues(values url.Values) string {
	mac := hmac.New(sha256.New, []byte(config.GetBootstrap().AuthCSRFProtectionSecretKey))
	mac.Write([]byte(values.Encode()))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// values preserves exact OAuth values across redirects, signatures and forms.
func (params ConsentParams) values() url.Values {
	return url.Values{
		"client_id": {params.ClientID}, "redirect_uri": {params.RedirectURI}, "scope": {params.Scope},
		"state": {params.State}, "nonce": {params.Nonce}, "code_challenge": {params.CodeChallenge},
		"code_challenge_method": {params.CodeChallengeMethod}, "prompt": {params.Prompt},
		"max_age": {params.MaxAge}, "consent_flow": {params.FlowToken},
	}
}
