package federation

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/eugenioenko/autentico/pkg/audit"
	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	"github.com/eugenioenko/autentico/pkg/reqid"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
	"golang.org/x/oauth2"
)

// HandleFederationIcon serves a provider's icon_svg with image/svg+xml content type.
// The login template references this via <img src> — SVGs loaded via <img> are
// processed by browsers in secure static mode (scripts and external resources
// disabled), neutralizing any malicious content in the admin-supplied SVG.
// The restrictive per-response CSP defends the case where someone navigates
// directly to the URL, treating the SVG as a top-level document.
func HandleFederationIcon(w http.ResponseWriter, r *http.Request) {
	providerID := r.PathValue("id")
	provider, err := FederationProviderByID(providerID)
	if err != nil || !provider.Enabled || !provider.IconSVG.Valid || provider.IconSVG.String == "" {
		http.NotFound(w, r)
		return
	}
	svg := []byte(provider.IconSVG.String)
	sum := sha256.Sum256(svg)
	etag := `"` + hex.EncodeToString(sum[:8]) + `"`
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; sandbox")
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "public, max-age=300, must-revalidate")
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	_, _ = w.Write(svg)
}

// HandleFederationBegin initiates an OIDC federation login by redirecting
// the user to the external identity provider.
func HandleFederationBegin(w http.ResponseWriter, r *http.Request) {
	providerID := r.PathValue("id")
	if providerID == "" {
		http.Error(w, "missing provider id", http.StatusBadRequest)
		return
	}

	provider, err := FederationProviderByID(providerID)
	if err != nil || !provider.Enabled {
		slog.Warn("federation: provider not found or disabled", "request_id", reqid.Get(r.Context()), "provider_id", providerID)
		http.Error(w, "federation provider not found", http.StatusNotFound)
		return
	}

	q := r.URL.Query()
	nonce, err := authcode.GenerateSecureCode()
	if err != nil {
		slog.Error("federation: failed to generate nonce", "request_id", reqid.Get(r.Context()), "error", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	state := FederationState{
		Nonce:               nonce,
		ProviderID:          providerID,
		RedirectURI:         q.Get("redirect_uri"),
		ClientID:            q.Get("client_id"),
		Scope:               q.Get("scope"),
		State:               q.Get("state"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
	}

	signedState, err := SignState(state)
	if err != nil {
		slog.Error("federation: failed to sign state", "request_id", reqid.Get(r.Context()), "error", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	// Use a restricted HTTP client to prevent SSRF via redirect following.
	safeCtx := context.WithValue(r.Context(), oauth2.HTTPClient, safeHTTPClient())
	oidcProvider, err := oidc.NewProvider(safeCtx, provider.Issuer)
	if err != nil {
		slog.Error("federation: failed to discover OIDC provider", "request_id", reqid.Get(r.Context()), "issuer", provider.Issuer, "error", err)
		http.Error(w, "federation provider unavailable", http.StatusBadGateway)
		return
	}

	oauth2Cfg := oauth2.Config{
		ClientID:     provider.ClientID,
		ClientSecret: provider.ClientSecret,
		Endpoint:     oidcProvider.Endpoint(),
		RedirectURL:  callbackURL(providerID),
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}

	authURL := oauth2Cfg.AuthCodeURL(signedState, oauth2.AccessTypeOnline)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// HandleFederationCallback handles the OIDC callback from the external provider,
// resolves the local user, and issues an authorization code.
func HandleFederationCallback(w http.ResponseWriter, r *http.Request) {
	providerID := r.PathValue("id")
	q := r.URL.Query()

	rawState := q.Get("state")
	code := q.Get("code")

	if rawState == "" || code == "" {
		slog.Warn("federation: missing state or code in callback", "request_id", reqid.Get(r.Context()), "provider_id", providerID)
		http.Error(w, "invalid callback", http.StatusBadRequest)
		return
	}

	state, err := VerifyState(rawState)
	if err != nil {
		slog.Warn("federation: invalid state signature", "request_id", reqid.Get(r.Context()), "provider_id", providerID, "error", err)
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}

	if state.ProviderID != providerID {
		slog.Warn("federation: provider_id mismatch in state", "request_id", reqid.Get(r.Context()), "expected", providerID, "got", state.ProviderID)
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}

	provider, err := FederationProviderByID(providerID)
	if err != nil || !provider.Enabled {
		slog.Warn("federation: provider not found or disabled in callback", "request_id", reqid.Get(r.Context()), "provider_id", providerID)
		http.Error(w, "federation provider not found", http.StatusNotFound)
		return
	}

	// Use a restricted HTTP client to prevent SSRF via redirect following.
	ctx := context.WithValue(r.Context(), oauth2.HTTPClient, safeHTTPClient())
	oidcProvider, err := oidc.NewProvider(ctx, provider.Issuer)
	if err != nil {
		slog.Error("federation: failed to discover OIDC provider in callback", "request_id", reqid.Get(r.Context()), "issuer", provider.Issuer, "error", err)
		http.Error(w, "federation provider unavailable", http.StatusBadGateway)
		return
	}

	oauth2Cfg := oauth2.Config{
		ClientID:     provider.ClientID,
		ClientSecret: provider.ClientSecret,
		Endpoint:     oidcProvider.Endpoint(),
		RedirectURL:  callbackURL(providerID),
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}

	token, err := oauth2Cfg.Exchange(ctx, code)
	if err != nil {
		slog.Warn("federation: failed to exchange code", "request_id", reqid.Get(r.Context()), "provider_id", providerID, "error", err)
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		slog.Warn("federation: no id_token in response", "request_id", reqid.Get(r.Context()), "provider_id", providerID)
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}

	verifier := oidcProvider.Verifier(&oidc.Config{ClientID: provider.ClientID})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		slog.Warn("federation: id_token verification failed", "request_id", reqid.Get(r.Context()), "provider_id", providerID, "error", err)
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}

	var claims struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := idToken.Claims(&claims); err != nil {
		slog.Error("federation: failed to extract claims", "request_id", reqid.Get(r.Context()), "provider_id", providerID, "error", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	usr, err := resolveUser(r.Context(), providerID, claims.Sub, claims.Email, claims.EmailVerified)
	if err != nil {
		slog.Error("federation: failed to resolve user", "request_id", reqid.Get(r.Context()), "provider_id", providerID, "error", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	audit.Log(audit.EventLoginSuccess, usr, audit.TargetUser, usr.ID, audit.Detail("method", "federation", "provider", providerID), utils.GetClientIP(r))

	if err := completeAuthFlow(w, r, usr, state); err != nil {
		slog.Error("federation: failed to complete auth flow", "request_id", reqid.Get(r.Context()), "provider_id", providerID, "error", err)
		http.Error(w, "server error", http.StatusInternalServerError)
	}
}

// resolveUser finds or creates the local user for a federated identity.
// Priority: (1) existing federated identity by (provider, sub),
// (2) verified email match on both sides, (3) new account.
func resolveUser(ctx context.Context, providerID, sub, email string, emailVerified bool) (*user.User, error) {
	// (1) Existing federated identity
	fi, err := FederatedIdentityByProviderAndSub(providerID, sub)
	if err == nil {
		usr, err := user.UserByID(fi.UserID)
		if err != nil {
			return nil, fmt.Errorf("federated user not found: %w", err)
		}
		return usr, nil
	}

	var localUser *user.User

	// (2) Auto-link by verified email (both sides must have verified it)
	if email != "" && emailVerified {
		existingUser, lookupErr := user.UserByEmail(email)
		if lookupErr == nil && existingUser.IsEmailVerified {
			localUser = existingUser
		}
	}

	// (3) Create new user if not matched
	if localUser == nil {
		var username string
		if config.Get().ProfileFieldEmail == "is_username" && email != "" {
			username = email
		} else {
			username = deriveUsername(email, sub)
		}
		_, createErr := user.CreateUser(username, randomPassword(), email)
		if createErr != nil {
			return nil, fmt.Errorf("failed to create federated user: %w", createErr)
		}
		newUser, lookupErr := user.UserByUsername(username)
		if lookupErr != nil {
			return nil, fmt.Errorf("failed to load created federated user: %w", lookupErr)
		}
		localUser = newUser
	}

	// Link the federated identity for future logins
	emailVal := sql.NullString{String: email, Valid: email != ""}
	_ = CreateFederatedIdentity(FederatedIdentity{
		ProviderID:     providerID,
		ProviderUserID: sub,
		UserID:         localUser.ID,
		Email:          emailVal,
	})

	return localUser, nil
}

// completeAuthFlow issues an auth code and redirects back to the client.
func completeAuthFlow(w http.ResponseWriter, r *http.Request, usr *user.User, state *FederationState) error {
	cfg := config.Get()

	var idpSessionID string
	sessionID, err := authcode.GenerateSecureCode()
	if err == nil {
		sess := idpsession.IdpSession{
			ID:        sessionID,
			UserID:    usr.ID,
			UserAgent: r.UserAgent(),
			IPAddress: utils.GetClientIP(r),
		}
		if idpsession.CreateIdpSession(sess) == nil {
			idpsession.SetCookie(w, sessionID)
			idpSessionID = sessionID
		}
	}

	authCode, err := authcode.GenerateSecureCode()
	if err != nil {
		return fmt.Errorf("failed to generate auth code: %w", err)
	}

	ac := authcode.AuthCode{
		Code:                authCode,
		UserID:              usr.ID,
		ClientID:            state.ClientID,
		RedirectURI:         state.RedirectURI,
		Scope:               state.Scope,
		Nonce:               state.Nonce,
		CodeChallenge:       state.CodeChallenge,
		CodeChallengeMethod: state.CodeChallengeMethod,
		ExpiresAt:           time.Now().Add(cfg.AuthAuthorizationCodeExpiration),
		Used:                false,
		IdpSessionID:        idpSessionID,
	}

	if err := authcode.CreateAuthCode(ac); err != nil {
		return fmt.Errorf("failed to create auth code: %w", err)
	}

	redirectURL := fmt.Sprintf("%s?code=%s&state=%s", state.RedirectURI, ac.Code, state.State)
	http.Redirect(w, r, redirectURL, http.StatusFound)
	return nil
}

// callbackURL builds the redirect_uri for a given provider.
func callbackURL(providerID string) string {
	return config.GetBootstrap().AppURL + config.GetBootstrap().AppOAuthPath + "/federation/" + providerID + "/callback"
}

// deriveUsername creates a unique username from the email address and sub.
func deriveUsername(email, sub string) string {
	prefix := sub
	if email != "" {
		at := strings.Index(email, "@")
		if at > 0 {
			prefix = email[:at]
		}
	}
	// Truncate prefix to avoid overly long usernames
	if len(prefix) > 20 {
		prefix = prefix[:20]
	}
	// Append a short random suffix from the sub for uniqueness
	suffix := sub
	if len(suffix) > 8 {
		suffix = suffix[len(suffix)-8:]
	}
	return prefix + "-" + suffix
}

// randomPassword generates a random unusable password for federated users.
func randomPassword() string {
	code, err := authcode.GenerateSecureCode()
	if err != nil {
		return "federated-" + fmt.Sprint(time.Now().UnixNano())
	}
	return code
}
