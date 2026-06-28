package magiclink

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/eugenioenko/autentico/pkg/audit"
	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/authzsig"
	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/consent"
	"github.com/eugenioenko/autentico/pkg/email"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	"github.com/eugenioenko/autentico/pkg/mfa"
	"github.com/eugenioenko/autentico/pkg/reqid"
	"github.com/eugenioenko/autentico/pkg/trusteddevice"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
	"github.com/eugenioenko/autentico/view"
	"github.com/gorilla/csrf"
)

const mfaChallengeExpiration = 10 * time.Minute

type oauthParams struct {
	RedirectURI         string
	State               string
	ClientID            string
	Scope               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
}

func paramsFromQuery(r *http.Request) oauthParams {
	q := r.URL.Query()
	return oauthParams{
		RedirectURI:         q.Get("redirect_uri"),
		State:               q.Get("state"),
		ClientID:            q.Get("client_id"),
		Scope:               q.Get("scope"),
		Nonce:               q.Get("nonce"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
	}
}

func paramsFromForm(r *http.Request) oauthParams {
	return oauthParams{
		RedirectURI:         r.FormValue("redirect_uri"),
		State:               r.FormValue("state"),
		ClientID:            r.FormValue("client_id"),
		Scope:               r.FormValue("scope"),
		Nonce:               r.FormValue("nonce"),
		CodeChallenge:       r.FormValue("code_challenge"),
		CodeChallengeMethod: r.FormValue("code_challenge_method"),
	}
}

func renderMagicLink(w http.ResponseWriter, r *http.Request, mode string, params oauthParams, authorizeSig, errMsg string, extra map[string]any) {
	cfg := config.Get()
	tmpl, err := view.ParseTemplate("magic_link")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	data := map[string]any{
		"Mode":                mode,
		"RedirectURI":         params.RedirectURI,
		"State":               params.State,
		"ClientID":            params.ClientID,
		"Scope":               params.Scope,
		"Nonce":               params.Nonce,
		"CodeChallenge":       params.CodeChallenge,
		"CodeChallengeMethod": params.CodeChallengeMethod,
		"AuthorizeSig":        authorizeSig,
		"Error":               errMsg,
		"ThemeTitle":          cfg.Theme.Title,
		"ThemeLogoUrl":        cfg.Theme.LogoUrl,
		csrf.TemplateTag:      csrf.TemplateField(r),
	}
	for k, v := range extra {
		data[k] = v
	}
	view.InjectNonce(r, data)
	if err = tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, "Template Execution Error", http.StatusInternalServerError)
	}
}

// HandleMagicLink handles GET and POST for /oauth2/magic-link.
// GET renders the email entry form. POST generates a magic link token and sends the email.
func HandleMagicLink(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if !cfg.MagicLinkEnabled {
		view.RenderError(w, r, http.StatusNotFound, "魔法链接登录未启用。")
		return
	}
	if cfg.SmtpHost == "" {
		view.RenderError(w, r, http.StatusServiceUnavailable, "邮件服务未配置。")
		return
	}

	if r.Method == http.MethodGet {
		params := paramsFromQuery(r)
		sig := authzsig.Sign(authzsig.AuthorizeParams{
			ClientID:            params.ClientID,
			RedirectURI:         params.RedirectURI,
			Scope:               params.Scope,
			Nonce:               params.Nonce,
			CodeChallenge:       params.CodeChallenge,
			CodeChallengeMethod: params.CodeChallengeMethod,
			State:               params.State,
		})
		renderMagicLink(w, r, "form", params, sig, "", nil)
		return
	}

	// POST
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	params := paramsFromForm(r)
	authorizeSigValue := r.FormValue("authorize_sig")
	emailAddr := r.FormValue("email")

	if emailAddr == "" {
		renderMagicLink(w, r, "form", params, authorizeSigValue, "请输入您的邮箱地址。", nil)
		return
	}

	sentExtra := map[string]any{"Email": emailAddr}

	// Verify HMAC signature to prevent parameter tampering
	if !authzsig.Verify(authzsig.AuthorizeParams{
		ClientID:            params.ClientID,
		RedirectURI:         params.RedirectURI,
		Scope:               params.Scope,
		Nonce:               params.Nonce,
		CodeChallenge:       params.CodeChallenge,
		CodeChallengeMethod: params.CodeChallengeMethod,
		State:               params.State,
	}, authorizeSigValue) {
		slog.Warn("magiclink: authorize parameter signature mismatch", "request_id", reqid.Get(r.Context()), "ip", utils.GetClientIP(r))
		view.RenderError(w, r, http.StatusBadRequest, "授权请求参数已被篡改。")
		return
	}

	utils.RandomDelay()

	reqID := reqid.Get(r.Context())

	// Look up user by verified email only
	usr, err := user.UserByEmail(emailAddr)
	if err != nil || usr == nil || usr.DeactivatedAt != nil {
		renderMagicLink(w, r, "sent", params, authorizeSigValue, "", sentExtra)
		return
	}

	invalidatePreviousTokens(usr.ID)

	rawToken, tokenHash, err := generateToken()
	if err != nil {
		slog.Error("magiclink: failed to generate token", "request_id", reqID, "error", err)
		renderMagicLink(w, r, "sent", params, authorizeSigValue, "", sentExtra)
		return
	}

	code, err := generateCode()
	if err != nil {
		slog.Error("magiclink: failed to generate code", "request_id", reqID, "error", err)
		renderMagicLink(w, r, "sent", params, authorizeSigValue, "", sentExtra)
		return
	}
	codeHash := utils.HashSHA256(code)

	expiresAt := time.Now().Add(cfg.MagicLinkExpiration)
	if err := createMagicLinkToken(usr.ID, tokenHash, codeHash, expiresAt); err != nil {
		slog.Error("magiclink: failed to store token", "request_id", reqID, "error", err)
		renderMagicLink(w, r, "sent", params, authorizeSigValue, "", sentExtra)
		return
	}

	audit.Log(audit.EventMagicLinkRequested, nil, audit.TargetUser, usr.ID, nil, utils.GetClientIP(r))

	magicLinkURL := buildMagicLinkURL(rawToken, params, authorizeSigValue)
	expirationMinutes := max(int(cfg.MagicLinkExpiration.Minutes()), 1)
	go func() {
		if err := email.SendMagicLinkEmail(usr.Email, magicLinkURL, code, expirationMinutes); err != nil {
			slog.Error("magiclink: failed to send email", "request_id", reqID, "error", err)
		}
	}()

	renderMagicLink(w, r, "sent", params, authorizeSigValue, "", sentExtra)
}

// HandleMagicLinkVerify handles GET for /oauth2/magic-link/verify.
// Validates the magic link token and completes the login flow.
func HandleMagicLinkVerify(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if !cfg.MagicLinkEnabled {
		view.RenderError(w, r, http.StatusNotFound, "魔法链接登录未启用。")
		return
	}

	params := paramsFromQuery(r)
	authorizeSigValue := r.URL.Query().Get("authorize_sig")
	rawToken := r.URL.Query().Get("token")

	if rawToken == "" {
		renderMagicLink(w, r, "expired", params, authorizeSigValue, "魔法链接无效或缺失。", nil)
		return
	}

	tokenHash := utils.HashSHA256(rawToken)
	userID, expiresAt, usedAt, err := getMagicLinkTokenInfo(tokenHash)
	if err != nil {
		if err == sql.ErrNoRows {
			renderMagicLink(w, r, "expired", params, authorizeSigValue, "此魔法链接无效或已被使用。", nil)
			return
		}
		slog.Error("magiclink: failed to look up token", "request_id", reqid.Get(r.Context()), "error", err)
		renderMagicLink(w, r, "expired", params, authorizeSigValue, "Something went wrong. Please request a new link.", nil)
		return
	}

	if usedAt != nil {
		renderMagicLink(w, r, "expired", params, authorizeSigValue, "This magic link has already been used.", nil)
		return
	}

	if time.Now().After(expiresAt) {
		renderMagicLink(w, r, "expired", params, authorizeSigValue, "This magic link has expired.", nil)
		return
	}

	markTokenUsed(tokenHash)

	completeLogin(w, r, cfg, params, authorizeSigValue, userID)
}

// HandleMagicLinkVerifyCode handles POST for /oauth2/magic-link/verify.
// Validates the 6-digit code and completes the login flow.
func HandleMagicLinkVerifyCode(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if !cfg.MagicLinkEnabled {
		view.RenderError(w, r, http.StatusNotFound, "魔法链接登录未启用。")
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	params := paramsFromForm(r)
	authorizeSigValue := r.FormValue("authorize_sig")
	emailAddr := r.FormValue("email")
	code := r.FormValue("code")
	sentExtra := map[string]any{"Email": emailAddr}

	if code == "" {
		renderMagicLink(w, r, "sent", params, authorizeSigValue, "Please enter the code from your email.", sentExtra)
		return
	}

	utils.RandomDelay()

	genericErr := "Invalid code. Please check and try again."
	usr, err := user.UserByEmail(emailAddr)
	if err != nil || usr == nil {
		renderMagicLink(w, r, "sent", params, authorizeSigValue, genericErr, sentExtra)
		return
	}

	codeHash := utils.HashSHA256(code)
	tokenHash, expiresAt, usedAt, err := getMagicLinkTokenByCodeHash(usr.ID, codeHash)
	if err != nil {
		if err == sql.ErrNoRows {
			renderMagicLink(w, r, "sent", params, authorizeSigValue, genericErr, sentExtra)
			return
		}
		slog.Error("magiclink: failed to look up code", "request_id", reqid.Get(r.Context()), "error", err)
		renderMagicLink(w, r, "sent", params, authorizeSigValue, genericErr, sentExtra)
		return
	}

	if usedAt != nil || time.Now().After(expiresAt) {
		renderMagicLink(w, r, "sent", params, authorizeSigValue, genericErr, sentExtra)
		return
	}

	markTokenUsed(tokenHash)

	completeLogin(w, r, cfg, params, authorizeSigValue, usr.ID)
}

// completeLogin performs the post-verification login flow: signature check,
// client validation, MFA, consent, IdP session, and auth code issuance.
func completeLogin(w http.ResponseWriter, r *http.Request, cfg *config.Config, params oauthParams, authorizeSigValue, userID string) {
	if !authzsig.Verify(authzsig.AuthorizeParams{
		ClientID:            params.ClientID,
		RedirectURI:         params.RedirectURI,
		Scope:               params.Scope,
		Nonce:               params.Nonce,
		CodeChallenge:       params.CodeChallenge,
		CodeChallengeMethod: params.CodeChallengeMethod,
		State:               params.State,
	}, authorizeSigValue) {
		slog.Warn("magiclink: authorize parameter signature mismatch on verify", "request_id", reqid.Get(r.Context()), "ip", utils.GetClientIP(r))
		view.RenderError(w, r, http.StatusBadRequest, "授权请求参数已被篡改。")
		return
	}

	registeredClient, err := client.ClientByClientID(params.ClientID)
	if err != nil {
		slog.Warn("magiclink: unknown client_id", "request_id", reqid.Get(r.Context()), "client_id", params.ClientID)
		view.RenderError(w, r, http.StatusBadRequest, "Unknown client.")
		return
	}
	if !registeredClient.IsActive {
		view.RenderError(w, r, http.StatusBadRequest, "Client is inactive.")
		return
	}
	if !client.IsValidRedirectURI(registeredClient, params.RedirectURI) {
		view.RenderError(w, r, http.StatusBadRequest, "Redirect URI not allowed for this client.")
		return
	}
	if !client.ValidateScopes(registeredClient, params.Scope) {
		view.RenderError(w, r, http.StatusBadRequest, "One or more requested scopes are not allowed for this client.")
		return
	}

	usr, err := user.UserByID(userID)
	if err != nil || usr == nil || usr.DeactivatedAt != nil {
		renderMagicLink(w, r, "expired", params, authorizeSigValue, "Account not found or deactivated.", nil)
		return
	}

	skipMfa := cfg.TrustDeviceEnabled && trusteddevice.IsDeviceTrusted(usr.ID, r)
	if (cfg.RequireMfa || usr.TotpVerified) && !skipMfa {
		method := cfg.MfaMethod
		if !cfg.RequireMfa && usr.TotpVerified {
			method = "totp"
		} else if method == "both" {
			if usr.TotpVerified {
				method = "totp"
			} else {
				method = "email"
			}
		}
		if method == "email" && cfg.SmtpHost == "" {
			if usr.TotpVerified {
				method = "totp"
			} else {
				slog.Error("magiclink: email MFA required but SMTP is not configured", "request_id", reqid.Get(r.Context()))
				view.RenderError(w, r, http.StatusServiceUnavailable, "Email verification is not available.")
				return
			}
		}
		// Magic link already proves email ownership — skip email OTP
		if method == "email" {
			slog.Info("magiclink: skipping email MFA — magic link already verified email ownership", "request_id", reqid.Get(r.Context()), "user_id", userID)
		} else {
			loginState := mfa.LoginState{
				RedirectURI:         params.RedirectURI,
				State:               params.State,
				ClientID:            params.ClientID,
				Scope:               params.Scope,
				Nonce:               params.Nonce,
				CodeChallenge:       params.CodeChallenge,
				CodeChallengeMethod: params.CodeChallengeMethod,
			}
			stateJSON, err := json.Marshal(loginState)
			if err != nil {
				slog.Error("magiclink: failed to serialize login state", "request_id", reqid.Get(r.Context()), "error", err)
				view.RenderError(w, r, http.StatusInternalServerError, "Something went wrong.")
				return
			}

			challengeID, err := authcode.GenerateSecureCode()
			if err != nil {
				slog.Error("magiclink: failed to generate challenge ID", "request_id", reqid.Get(r.Context()), "error", err)
				view.RenderError(w, r, http.StatusInternalServerError, "Something went wrong.")
				return
			}

			challenge := mfa.MfaChallenge{
				ID:         challengeID,
				UserID:     usr.ID,
				Method:     method,
				LoginState: string(stateJSON),
				ExpiresAt:  time.Now().Add(mfaChallengeExpiration),
			}

			if err := mfa.CreateMfaChallenge(challenge); err != nil {
				slog.Error("magiclink: failed to create MFA challenge", "request_id", reqid.Get(r.Context()), "error", err)
				view.RenderError(w, r, http.StatusInternalServerError, "Something went wrong.")
				return
			}

			mfaURL := config.GetBootstrap().AppOAuthPath + "/mfa?challenge_id=" + challengeID
			http.Redirect(w, r, mfaURL, http.StatusFound)
			return
		}
	}

	idpSessionID := idpsession.FinalizeLogin(w, r, usr.ID)

	if consent.NeedsConsent(registeredClient.ConsentRequired, usr.ID, params.ClientID, params.Scope, "") {
		consent.RedirectToConsent(w, r, consent.ConsentParams{
			RedirectURI:         params.RedirectURI,
			State:               params.State,
			ClientID:            params.ClientID,
			Scope:               params.Scope,
			Nonce:               params.Nonce,
			CodeChallenge:       params.CodeChallenge,
			CodeChallengeMethod: params.CodeChallengeMethod,
		})
		return
	}

	authCodeValue, err := authcode.GenerateSecureCode()
	if err != nil {
		slog.Error("magiclink: failed to generate auth code", "request_id", reqid.Get(r.Context()), "error", err)
		view.RenderError(w, r, http.StatusInternalServerError, "Something went wrong.")
		return
	}

	codeRecord := authcode.AuthCode{
		Code:                authCodeValue,
		UserID:              usr.ID,
		ClientID:            params.ClientID,
		RedirectURI:         params.RedirectURI,
		Scope:               params.Scope,
		Nonce:               params.Nonce,
		CodeChallenge:       params.CodeChallenge,
		CodeChallengeMethod: params.CodeChallengeMethod,
		ExpiresAt:           time.Now().Add(cfg.AuthAuthorizationCodeExpiration),
		Used:                false,
		IdpSessionID:        idpSessionID,
	}

	if err := authcode.CreateAuthCode(codeRecord); err != nil {
		slog.Error("magiclink: failed to create auth code", "request_id", reqid.Get(r.Context()), "error", err)
		view.RenderError(w, r, http.StatusInternalServerError, "Something went wrong.")
		return
	}

	audit.Log(audit.EventMagicLinkLoginSuccess, usr, audit.TargetUser, usr.ID, audit.Detail("method", "magic_link"), utils.GetClientIP(r))

	redirectParams := url.Values{}
	redirectParams.Set("code", codeRecord.Code)
	if params.State != "" {
		redirectParams.Set("state", params.State)
	}
	http.Redirect(w, r, params.RedirectURI+"?"+redirectParams.Encode(), http.StatusFound)
}

func buildMagicLinkURL(rawToken string, p oauthParams, authorizeSig string) string {
	bs := config.GetBootstrap()
	q := url.Values{}
	q.Set("token", rawToken)
	q.Set("redirect_uri", p.RedirectURI)
	q.Set("state", p.State)
	q.Set("client_id", p.ClientID)
	q.Set("scope", p.Scope)
	q.Set("authorize_sig", authorizeSig)
	if p.Nonce != "" {
		q.Set("nonce", p.Nonce)
	}
	if p.CodeChallenge != "" {
		q.Set("code_challenge", p.CodeChallenge)
		q.Set("code_challenge_method", p.CodeChallengeMethod)
	}
	return bs.AppURL + bs.AppOAuthPath + "/magic-link/verify?" + q.Encode()
}
