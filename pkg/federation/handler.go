package federation

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/mfa"
	"github.com/eugenioenko/autentico/pkg/reqid"
	"github.com/eugenioenko/autentico/pkg/user"
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
	if providerID == "" {
		http.NotFound(w, r)
		return
	}
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

// LoginHandler holds the outbound client used for a federation login.
// Construct with NewLoginHandler(nil) to enforce the production SSRF policy.
type LoginHandler struct{ httpClient *http.Client }

// NewLoginHandler creates isolated login handlers; nil selects the restricted client.
// An explicit client supports trusted in-process integrations such as local OIDC test fixtures.
func NewLoginHandler(httpClient *http.Client) *LoginHandler {
	if httpClient == nil {
		httpClient = safeHTTPClient()
	}
	return &LoginHandler{httpClient: httpClient}
}

// HandleFederationBegin initiates an OIDC federation login by redirecting
// the user to the external identity provider.
func HandleFederationBegin(w http.ResponseWriter, r *http.Request) {
	NewLoginHandler(nil).HandleBegin(w, r)
}

// HandleBegin validates the client and initiates discovery with this handler's outbound client.
func (h *LoginHandler) HandleBegin(w http.ResponseWriter, r *http.Request) {
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
	state := FederationState{
		// OIDC Core §3.1.2.1 / §3.1.3.7: the client's nonce must be returned unmodified in the ID token
		Nonce:               q.Get("nonce"),
		ProviderID:          providerID,
		RedirectURI:         q.Get("redirect_uri"),
		ClientID:            q.Get("client_id"),
		Scope:               q.Get("scope"),
		State:               q.Get("state"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
		Prompt:              q.Get("prompt"),
		MaxAge:              q.Get("max_age"),
	}

	// RFC 6749 §4.1.2.1 / §10.6: validate before signing or contacting the provider;
	// never redirect an invalid request to an attacker-controlled URI.
	if _, err := client.ValidateAuthorization(state.authorizeParams()); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Use a restricted HTTP client to prevent SSRF on every outbound connection.
	safeCtx := context.WithValue(r.Context(), oauth2.HTTPClient, h.httpClient)
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

	// RFC 6749 §10.12 / RFC 9700 §4.7.1: persist the browser-bound,
	// expiring one-use state only after successful provider discovery.
	signedState, cookie, err := beginLoginFlow(r, &state)
	if err != nil {
		slog.Error("federation: failed to create login flow", "request_id", reqid.Get(r.Context()), "error", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	// OIDC Core §3.1.2.1 / §3.1.3.7: the upstream nonce is independent
	// of the RP's nonce and binds its ID token to this exact flow.
	authURL := oauth2Cfg.AuthCodeURL(signedState, oauth2.AccessTypeOnline, oauth2.SetAuthURLParam("nonce", state.FlowID))
	http.SetCookie(w, cookie)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// HandleFederationCallback handles the OIDC callback from the external provider,
// resolves the local user, and issues an authorization code.
func HandleFederationCallback(w http.ResponseWriter, r *http.Request) {
	NewLoginHandler(nil).HandleCallback(w, r)
}

// HandleCallback completes discovery, code exchange and signature verification with one client.
func (h *LoginHandler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	providerID := r.PathValue("id")
	if providerID == "" {
		http.Error(w, "missing provider id", http.StatusBadRequest)
		return
	}
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

	// RFC 6749 §4.1.1 / §10.6: the registration may have changed since begin.
	// A valid state signature alone does not authorize the client or redirect URI.
	if _, err := client.ValidateAuthorization(state.authorizeParams()); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	provider, err := FederationProviderByID(providerID)
	if err != nil || !provider.Enabled {
		slog.Warn("federation: provider not found or disabled in callback", "request_id", reqid.Get(r.Context()), "provider_id", providerID)
		http.Error(w, "federation provider not found", http.StatusNotFound)
		return
	}

	// RFC 6749 §10.12 / RFC 9700 §4.7.1: commit single-use browser
	// correlation before contacting the upstream or changing local accounts.
	if err := consumeLoginFlow(r, state, rawState); err != nil {
		if errors.Is(err, errInvalidLoginFlow) {
			http.Error(w, "invalid or expired federation login", http.StatusBadRequest)
		} else {
			slog.Error("federation: failed to consume login flow", "request_id", reqid.Get(r.Context()), "error", err)
			http.Error(w, "server error", http.StatusInternalServerError)
		}
		return
	}

	// Use a restricted HTTP client to prevent SSRF on every outbound connection.
	ctx := context.WithValue(r.Context(), oauth2.HTTPClient, h.httpClient)
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

	// OIDC Core §3.1.3.7: an ID token must echo the nonce sent upstream.
	// Reject before account resolution; the RP nonce remains state.Nonce.
	if idToken.Nonce != state.FlowID {
		slog.Warn("federation: upstream nonce mismatch", "request_id", reqid.Get(r.Context()), "provider_id", providerID)
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}

	var claims struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		GivenName     string `json:"given_name"`
		FamilyName    string `json:"family_name"`
	}
	if err := idToken.Claims(&claims); err != nil {
		slog.Error("federation: failed to extract claims", "request_id", reqid.Get(r.Context()), "provider_id", providerID, "error", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	// RFC 6749 §4.1.1 / §10.6: upstream HTTP calls can outlive a registration
	// change. Reject it before creating or linking a local account.
	if _, err := client.ValidateAuthorization(state.authorizeParams()); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	usr, err := resolveUser(r.Context(), providerID, claims.Sub, claims.Email, claims.EmailVerified, claims.GivenName, claims.FamilyName)
	if err != nil {
		slog.Error("federation: failed to resolve user", "request_id", reqid.Get(r.Context()), "provider_id", providerID, "error", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	if err := completeAuthFlow(w, r, usr, state); err != nil {
		slog.Error("federation: failed to complete auth flow", "request_id", reqid.Get(r.Context()), "provider_id", providerID, "error", err)
		http.Error(w, "server error", http.StatusInternalServerError)
	}
}

// resolveUser finds or creates the local user for a federated identity.
// Priority: (1) existing federated identity by (provider, sub),
// (2) verified email match on both sides, (3) new account.
func resolveUser(ctx context.Context, providerID, sub, email string, emailVerified bool, givenName, familyName string) (*user.User, error) {
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
		createdUser, createErr := user.CreateUser(username, randomPassword(), email)
		if createErr != nil {
			return nil, fmt.Errorf("failed to create federated user: %w", createErr)
		}
		if config.Get().FederationCopyNameClaims && (givenName != "" || familyName != "") {
			if err := user.UpdateUser(createdUser.ID, user.UserUpdateRequest{
				GivenName: givenName, FamilyName: familyName,
			}); err != nil {
				return nil, fmt.Errorf("failed to save federated name claims: %w", err)
			}
		}
		if email != "" && emailVerified {
			if err := user.MarkEmailVerified(createdUser.ID); err != nil {
				return nil, fmt.Errorf("failed to mark federated email verified: %w", err)
			}
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

// completeAuthFlow continues local MFA and consent after upstream authentication.
func completeAuthFlow(w http.ResponseWriter, r *http.Request, usr *user.User, state *FederationState) error {
	// OIDC Core §3.1.2.3–4: upstream authentication is a primary credential;
	// it does not assert completion of this server's configured local MFA.
	nextURL, err := mfa.FinishLogin(w, r, usr.ID, mfa.LoginState{
		ProviderID:          state.ProviderID,
		RedirectURI:         state.RedirectURI,
		State:               state.State,
		ClientID:            state.ClientID,
		Scope:               state.Scope,
		Nonce:               state.Nonce,
		CodeChallenge:       state.CodeChallenge,
		CodeChallengeMethod: state.CodeChallengeMethod,
		Prompt:              state.Prompt,
		MaxAge:              state.MaxAge,
	}, mfa.PrimaryFederation)
	if err != nil {
		return err
	}
	// RFC 6749 §4.1.2: follow the validated next authentication step.
	http.Redirect(w, r, nextURL, http.StatusFound)
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
