package cli

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/urfave/cli/v2"

	"github.com/eugenioenko/autentico/docs"
	"github.com/eugenioenko/autentico/pkg/account"
	"github.com/eugenioenko/autentico/pkg/admin"
	"github.com/eugenioenko/autentico/pkg/appsettings"
	"github.com/eugenioenko/autentico/pkg/audit"
	"github.com/eugenioenko/autentico/pkg/authorize"
	"github.com/eugenioenko/autentico/pkg/cleanup"
	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/cspnonce"
	"github.com/eugenioenko/autentico/pkg/consent"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/db/migrations"
	"github.com/eugenioenko/autentico/pkg/deletion"
	"github.com/eugenioenko/autentico/pkg/devicecode"
	"github.com/eugenioenko/autentico/pkg/emailverification"
	"github.com/eugenioenko/autentico/pkg/federation"
	"github.com/eugenioenko/autentico/pkg/group"
	"github.com/eugenioenko/autentico/pkg/health"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	"github.com/eugenioenko/autentico/pkg/introspect"
	"github.com/eugenioenko/autentico/pkg/key"
	"github.com/eugenioenko/autentico/pkg/login"
	"github.com/eugenioenko/autentico/pkg/magiclink"
	"github.com/eugenioenko/autentico/pkg/mfa"
	"github.com/eugenioenko/autentico/pkg/middleware"
	"github.com/eugenioenko/autentico/pkg/onboarding"
	"github.com/eugenioenko/autentico/pkg/passkey"
	"github.com/eugenioenko/autentico/pkg/passwordreset"
	"github.com/eugenioenko/autentico/pkg/ratelimit"
	"github.com/eugenioenko/autentico/pkg/reqid"
	"github.com/eugenioenko/autentico/pkg/revoke"
	"github.com/eugenioenko/autentico/pkg/session"
	"github.com/eugenioenko/autentico/pkg/signup"
	"github.com/eugenioenko/autentico/pkg/token"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/userinfo"
	"github.com/eugenioenko/autentico/pkg/wellknown"
	"github.com/eugenioenko/autentico/view"
	httpSwagger "github.com/swaggo/http-swagger"
)

func RunStart(c *cli.Context) error {
	if c.Bool("auto-setup") {
		if err := autoGenerateConfig(c.String("url"), c.Bool("dev")); err != nil {
			return err
		}
	}

	config.InitBootstrap()

	bs := config.GetBootstrap()

	if u, err := url.Parse(bs.AppURL); err == nil {
		docs.SwaggerInfo.Host = u.Host
		docs.SwaggerInfo.Schemes = []string{u.Scheme}
	}

	if err := validateBootstrapSecrets(bs); err != nil {
		return err
	}

	if _, err := db.InitDB(bs.DbFilePath); err != nil {
		absPath, _ := filepath.Abs(bs.DbFilePath)
		return fmt.Errorf("failed to initialize database at %s: %w", absPath, err)
	}
	defer db.CloseDB()

	if !c.Bool("no-auto-migrate") {
		if err := migrations.Run(db.GetWriteDB(), true); err != nil {
			return err
		}
	} else if err := migrations.Check(db.GetWriteDB()); err != nil {
		return err
	}

	// Load soft settings from DB into config.Values, writing defaults for any missing keys
	if err := appsettings.EnsureDefaults(); err != nil {
		log.Printf("warning: could not ensure settings defaults: %v", err)
	}
	if err := appsettings.LoadIntoConfig(); err != nil {
		log.Printf("warning: could not load settings from DB: %v", err)
	}

	// Initialize RSA key (from env var or ephemeral with warning)
	key.GetPrivateKey()

	// Auto-seed required OAuth2 clients
	seedAdminClient(false)
	seedAccountClient()

	cfg := config.Get()
	oauth := bs.AppOAuthPath
	mux := http.NewServeMux()

	// Per-IP rate limiter for authentication endpoints (rps=0 disables)
	limiterStore := ratelimit.NewStore(bs.RateLimitRPS, bs.RateLimitBurst, bs.RateLimitRPM, bs.RateLimitRPMBurst)
	rateLimited := middleware.RateLimitMiddleware(limiterStore)
	rateLimitedFunc := func(h http.HandlerFunc) http.Handler { return rateLimited(h) }
	adminAPI := func(h http.HandlerFunc) http.Handler { return middleware.AdminAuthMiddleware(h) }
	accountAPI := func(h http.HandlerFunc) http.Handler { return middleware.AccountAuthMiddleware(h) }
	csrfProtected := func(h http.HandlerFunc) http.Handler { return middleware.CSRFMiddleware(h) }

	// -------------------------------------------------------------------------
	// Infrastructure
	// -------------------------------------------------------------------------
	mux.HandleFunc("GET /healthz", health.HandleHealth)
	mux.Handle("/swagger/", httpSwagger.WrapHandler)
	mux.HandleFunc("GET /api-docs/", admin.ApiDocsHandler())
	mux.HandleFunc("GET /api-docs", admin.ApiDocsHandler())

	// -------------------------------------------------------------------------
	// OIDC discovery (public, no auth)
	// -------------------------------------------------------------------------
	mux.HandleFunc("GET /.well-known/openid-configuration", wellknown.HandleWellKnownConfig)
	mux.HandleFunc("GET "+oauth+"/.well-known/openid-configuration", wellknown.HandleWellKnownConfig)
	mux.HandleFunc("GET "+oauth+"/.well-known/jwks.json", wellknown.HandleJWKS)

	// -------------------------------------------------------------------------
	// OAuth2 / OIDC protocol endpoints
	// -------------------------------------------------------------------------

	mux.Handle("GET "+oauth+"/authorize", rateLimited(csrfProtected(authorize.HandleAuthorize)))
	mux.Handle("POST "+oauth+"/authorize", rateLimitedFunc(authorize.HandleAuthorize))
	mux.Handle(oauth+"/login", rateLimited(csrfProtected(login.HandleLoginUser)))
	mux.Handle(oauth+"/consent", csrfProtected(consent.HandleConsent))
	mux.Handle(oauth+"/mfa", rateLimited(csrfProtected(mfa.HandleMfa)))
	mux.Handle(oauth+"/mfa/", rateLimited(csrfProtected(mfa.HandleMfa)))
	mux.Handle("GET "+oauth+"/passkey/login/begin", rateLimitedFunc(passkey.HandleLoginBegin))
	mux.Handle("POST "+oauth+"/passkey/login/finish", rateLimitedFunc(passkey.HandleLoginFinish))
	mux.Handle("GET "+oauth+"/passkey/discoverable/begin", rateLimitedFunc(passkey.HandleDiscoverableLoginBegin))
	mux.Handle("POST "+oauth+"/passkey/discoverable/finish", rateLimitedFunc(passkey.HandleDiscoverableLoginFinish))
	mux.HandleFunc("GET "+oauth+"/passkey/register/begin", passkey.HandleRegisterBegin)
	mux.HandleFunc("POST "+oauth+"/passkey/register/finish", passkey.HandleRegisterFinish)
	mux.Handle("GET "+oauth+"/verify-email", rateLimited(csrfProtected(emailverification.HandleVerifyEmail)))
	mux.Handle("POST "+oauth+"/resend-verification", rateLimited(csrfProtected(emailverification.HandleResendVerification)))
	mux.Handle(oauth+"/magic-link", rateLimited(csrfProtected(magiclink.HandleMagicLink)))
	mux.Handle("GET "+oauth+"/magic-link/verify", rateLimited(csrfProtected(magiclink.HandleMagicLinkVerify)))
	mux.Handle("POST "+oauth+"/magic-link/verify", rateLimited(csrfProtected(magiclink.HandleMagicLinkVerifyCode)))
	mux.Handle(oauth+"/forgot-password", rateLimited(csrfProtected(passwordreset.HandleForgotPassword)))
	mux.Handle(oauth+"/reset-password", rateLimited(csrfProtected(passwordreset.HandleResetPassword)))
	mux.HandleFunc("GET "+oauth+"/federation/{id}", federation.HandleFederationBegin)
	mux.HandleFunc("GET "+oauth+"/federation/{id}/callback", federation.HandleFederationCallback)
	mux.Handle(oauth+"/signup", csrfProtected(signup.HandleSignup))
	mux.Handle(oauth+"/signup/", csrfProtected(signup.HandleSignup))
	mux.Handle("POST "+oauth+"/token", rateLimitedFunc(token.HandleToken))
	mux.Handle("POST "+oauth+"/protocol/openid-connect/token", rateLimitedFunc(token.HandleToken))
	mux.Handle("POST "+oauth+"/device_authorization", rateLimitedFunc(devicecode.HandleDeviceAuthorization))
	mux.Handle("POST "+oauth+"/revoke", rateLimitedFunc(revoke.HandleRevoke))
	mux.Handle("POST "+oauth+"/introspect", rateLimitedFunc(introspect.HandleIntrospect))
	mux.Handle(oauth+"/userinfo", rateLimitedFunc(userinfo.HandleUserInfo))
	mux.Handle(oauth+"/protocol/openid-connect/userinfo", rateLimitedFunc(userinfo.HandleUserInfo))
	mux.HandleFunc("POST "+oauth+"/logout", session.HandleLogout)
	mux.HandleFunc("GET "+oauth+"/logout", session.HandleRpInitiatedLogout)
	mux.Handle("POST "+oauth+"/register", adminAPI(client.HandleRegister))
	mux.Handle("GET "+oauth+"/register/{client_id}", adminAPI(client.HandleGetClient))
	mux.Handle("PUT "+oauth+"/register/{client_id}", adminAPI(client.HandleUpdateClient))
	mux.Handle("DELETE "+oauth+"/register/{client_id}", adminAPI(client.HandleDeleteClient))

	// -------------------------------------------------------------------------
	// Admin API (admin-authenticated)
	// -------------------------------------------------------------------------
	mux.Handle("GET /admin/api/users", adminAPI(user.HandleListUsers))
	mux.Handle("POST /admin/api/users", adminAPI(user.HandleCreateUser))
	mux.Handle("GET /admin/api/users/{id}", adminAPI(user.HandleGetUser))
	mux.Handle("PUT /admin/api/users/{id}", adminAPI(user.HandleUpdateUser))
	mux.Handle("DELETE /admin/api/users/{id}", adminAPI(user.HandleDeleteUser))
	mux.Handle("POST /admin/api/users/{id}/deactivate", adminAPI(user.HandleDeactivateUser))
	mux.Handle("POST /admin/api/users/{id}/reactivate", adminAPI(user.HandleReactivateUser))
	mux.Handle("POST /admin/api/users/{id}/unlock", adminAPI(user.HandleUnlockUser))
	mux.Handle("POST /admin/api/users/{id}/revoke-sessions", adminAPI(user.HandleRevokeUserSessions))
	mux.Handle("POST /admin/api/users/lookup", adminAPI(user.HandleLookupUsers))
	mux.Handle("GET /admin/api/clients", adminAPI(client.HandleAdminListClients))
	mux.Handle("POST /admin/api/clients", adminAPI(client.HandleRegister))
	mux.Handle("GET /admin/api/clients/{client_id}", adminAPI(client.HandleGetClient))
	mux.Handle("PUT /admin/api/clients/{client_id}", adminAPI(client.HandleUpdateClient))
	mux.Handle("DELETE /admin/api/clients/{client_id}", adminAPI(client.HandleDeleteClient))
	mux.Handle("GET /admin/api/sessions", adminAPI(session.HandleListSessions))
	mux.Handle("DELETE /admin/api/sessions/{id}", adminAPI(session.HandleDeactivateSession))
	mux.Handle("GET /admin/api/idp-sessions", adminAPI(idpsession.HandleListIdpSessions))
	mux.Handle("GET /admin/api/users/{id}/idp-sessions", adminAPI(idpsession.HandleListUserIdpSessions))
	mux.Handle("GET /admin/api/idp-sessions/{id}/sessions", adminAPI(session.HandleListIdpSessionSessions))
	mux.Handle("DELETE /admin/api/idp-sessions/{id}", adminAPI(idpsession.HandleForceLogoutIdpSession))
	mux.Handle("GET /admin/api/federation", adminAPI(federation.HandleListProviders))
	mux.Handle("POST /admin/api/federation", adminAPI(federation.HandleCreateProvider))
	mux.Handle("GET /admin/api/federation/{id}", adminAPI(federation.HandleGetProvider))
	mux.Handle("PUT /admin/api/federation/{id}", adminAPI(federation.HandleUpdateProvider))
	mux.Handle("DELETE /admin/api/federation/{id}", adminAPI(federation.HandleDeleteProvider))
	mux.Handle("GET /admin/api/groups", adminAPI(group.HandleListGroups))
	mux.Handle("POST /admin/api/groups", adminAPI(group.HandleCreateGroup))
	mux.Handle("GET /admin/api/groups/{id}", adminAPI(group.HandleGetGroup))
	mux.Handle("PUT /admin/api/groups/{id}", adminAPI(group.HandleUpdateGroup))
	mux.Handle("DELETE /admin/api/groups/{id}", adminAPI(group.HandleDeleteGroup))
	mux.Handle("GET /admin/api/groups/{id}/members", adminAPI(group.HandleListMembers))
	mux.Handle("POST /admin/api/groups/{id}/members", adminAPI(group.HandleAddMember))
	mux.Handle("DELETE /admin/api/groups/{id}/members/{user_id}", adminAPI(group.HandleRemoveMember))
	mux.Handle("GET /admin/api/users/{id}/groups", adminAPI(group.HandleGetUserGroups))
	mux.Handle("GET /admin/api/tokens", adminAPI(token.HandleListTokens))
	mux.Handle("DELETE /admin/api/tokens/{id}", adminAPI(token.HandleRevokeToken))
	mux.Handle("GET /admin/api/stats", adminAPI(admin.HandleStats))
	mux.Handle("GET /admin/api/settings", adminAPI(appsettings.HandleGetSettings))
	mux.Handle("PUT /admin/api/settings", adminAPI(appsettings.HandlePutSettings))
	mux.Handle("POST /admin/api/settings/test-smtp", adminAPI(appsettings.HandleTestSmtp))
	mux.Handle("GET /admin/api/settings/export", adminAPI(appsettings.HandleExportSettings))
	mux.Handle("POST /admin/api/settings/import/preview", adminAPI(appsettings.HandleImportPreview))
	mux.Handle("POST /admin/api/settings/import/apply", adminAPI(appsettings.HandleImportApply))
	mux.Handle("GET /admin/api/audit-logs", adminAPI(audit.HandleListAuditLogs))
	mux.Handle("GET /admin/api/deletion-requests", adminAPI(deletion.HandleListDeletionRequests))
	mux.Handle("POST /admin/api/deletion-requests/{id}/approve", adminAPI(deletion.HandleApproveDeletionRequest))
	mux.Handle("DELETE /admin/api/deletion-requests/{id}", adminAPI(deletion.HandleAdminCancelDeletionRequest))

	// -------------------------------------------------------------------------
	// Account self-service API (audience: autentico-account or autentico-admin)
	// -------------------------------------------------------------------------
	mux.Handle("GET /account/api/profile", accountAPI(account.HandleGetProfile))
	mux.Handle("PUT /account/api/profile", accountAPI(account.HandleUpdateProfile))
	mux.Handle("POST /account/api/password", rateLimited(middleware.AccountAuthMiddleware(http.HandlerFunc(account.HandleUpdatePassword))))
	mux.Handle("GET /account/api/sessions", accountAPI(account.HandleListSessions))
	mux.Handle("DELETE /account/api/sessions/{id}", accountAPI(account.HandleRevokeSession))
	mux.Handle("POST /account/api/sessions/revoke-others", accountAPI(account.HandleRevokeOtherSessions))
	mux.Handle("GET /account/api/passkeys", accountAPI(account.HandleListPasskeys))
	mux.Handle("DELETE /account/api/passkeys/{id}", accountAPI(account.HandleDeletePasskey))
	mux.Handle("PATCH /account/api/passkeys/{id}", accountAPI(account.HandleRenamePasskey))
	mux.Handle("POST /account/api/passkeys/register/begin", accountAPI(account.HandleAddPasskeyBegin))
	mux.Handle("POST /account/api/passkeys/register/finish", accountAPI(account.HandleAddPasskeyFinish))
	mux.Handle("GET /account/api/mfa", accountAPI(account.HandleGetMfaStatus))
	mux.Handle("POST /account/api/mfa/totp/setup", accountAPI(account.HandleSetupTotp))
	mux.Handle("POST /account/api/mfa/totp/verify", accountAPI(account.HandleVerifyTotp))
	mux.Handle("DELETE /account/api/mfa/totp", rateLimited(middleware.AccountAuthMiddleware(http.HandlerFunc(account.HandleDeleteMfa))))
	mux.Handle("GET /account/api/trusted-devices", accountAPI(account.HandleListTrustedDevices))
	mux.Handle("DELETE /account/api/trusted-devices/{id}", accountAPI(account.HandleRevokeTrustedDevice))
	mux.Handle("GET /account/api/connected-providers", accountAPI(account.HandleListConnectedProviders))
	mux.Handle("DELETE /account/api/connected-providers/{id}", accountAPI(account.HandleDisconnectProvider))
	mux.Handle("POST /account/api/device/verify", rateLimited(accountAPI(account.HandleDeviceVerify)))
	mux.Handle("POST /account/api/device/authorize", rateLimited(accountAPI(account.HandleDeviceAuthorize)))
	mux.Handle("POST /account/api/device/deny", rateLimited(accountAPI(account.HandleDeviceDeny)))
	mux.HandleFunc("GET /account/api/settings", account.HandleGetSettings)
	mux.Handle("GET /account/api/deletion-request", accountAPI(deletion.HandleGetDeletionRequest))
	mux.Handle("POST /account/api/deletion-request", accountAPI(deletion.HandleRequestDeletion))
	mux.Handle("DELETE /account/api/deletion-request", accountAPI(deletion.HandleCancelDeletionRequest))

	// -------------------------------------------------------------------------
	// Embedded UIs
	// -------------------------------------------------------------------------
	mux.Handle("/admin/", admin.Handler())
	mux.Handle("/account/", account.Handler())
	mux.Handle("GET "+oauth+"/static/theme.css", view.ThemeCSSHandler())
	mux.HandleFunc("GET "+oauth+"/federation/{id}/icon.svg", federation.HandleFederationIcon)
	mux.Handle(oauth+"/static/", http.StripPrefix(oauth+"/static/", view.StaticHandler()))

	// -------------------------------------------------------------------------
	// First-time onboarding (only if no users exist, otherwise redirect to login)
	// -------------------------------------------------------------------------
	mux.Handle("/onboard", csrfProtected(onboarding.HandleOnboardDirect))
	mux.Handle("/onboard/", csrfProtected(onboarding.HandleOnboardDirect))

	// Root redirect — send visitors to the account profile page
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/account/", http.StatusFound)
			return
		}
		http.NotFound(w, r)
	})

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cleanup.Start(ctx, cfg.CleanupInterval, cfg.CleanupRetention, func() {
		limiterStore.Cleanup(10 * time.Minute)
	})

	baseURL := bs.AppURL
	fmt.Println()
	fmt.Printf("  Autentico OIDC Identity Provider %s\n", Version)
	fmt.Println()

	if !appsettings.IsOnboarded() {
		fmt.Printf("  ONBOARDING: %s/onboard/\n", baseURL)
		fmt.Println()
	}

	fmt.Printf("  Server:     %s\n", baseURL)
	fmt.Printf("  Admin UI:   %s/admin/\n", baseURL)
	fmt.Printf("  Account UI: %s/account/\n", baseURL)
	fmt.Println()
	fmt.Printf("  API Docs:   %s/api-docs/\n", baseURL)
	fmt.Printf("  Swagger:    %s/swagger/index.html\n", baseURL)
	fmt.Printf("  Docs:       https://autentico.top\n")
	fmt.Println()
	fmt.Printf("  Issuer:     %s%s\n", baseURL, oauth)
	fmt.Printf("  WellKnown:  %s%s/.well-known/openid-configuration\n", baseURL, oauth)
	fmt.Printf("  JWKS:       %s%s/.well-known/jwks.json\n", baseURL, oauth)
	fmt.Printf("  Authorize:  %s%s/authorize\n", baseURL, oauth)
	fmt.Printf("  Token:      %s%s/token\n", baseURL, oauth)
	fmt.Println()
	fmt.Printf("  SQLite:     1 writer, %d readers (WAL mode)\n", db.ReadPoolSize())
	fmt.Println()

	middlewareList := []func(http.Handler) http.Handler{
		reqid.Middleware,
		cspnonce.Middleware,
		middleware.SecurityHeadersMiddleware,
		middleware.LoggingMiddleware,
		middleware.CORSMiddleware,
	}
	combinedMiddleware := middleware.CombineMiddlewares(middlewareList)

	srv := &http.Server{
		Addr:    ":" + bs.AppListenPort,
		Handler: combinedMiddleware(mux),
	}

	go func() {
		<-ctx.Done()
		if err := srv.Shutdown(context.Background()); err != nil {
			log.Printf("server shutdown error: %v", err)
		}
	}()

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// seedAdminClient creates the autentico-admin OAuth2 client if it does not already exist.
// When enablePasswordGrant is true, "password" is included in grant_types so the client
// can issue admin-API tokens headlessly for CI automation (RFC 6749 §4.3 / ROPC).
func seedAdminClient(enablePasswordGrant bool) {
	const clientName = "Autentico Admin UI"
	if existing, err := client.ClientByClientID(config.AdminClientID); err == nil && existing != nil {
		return
	}
	grantTypes := []string{"authorization_code", "refresh_token"}
	if enablePasswordGrant {
		grantTypes = append(grantTypes, "password")
	}
	redirectURI := config.GetBootstrap().AppURL + "/admin/callback"
	if _, err := client.CreateClientWithID(config.AdminClientID, client.ClientCreateRequest{
		ClientName:              clientName,
		RedirectURIs:            []string{redirectURI},
		GrantTypes:              grantTypes,
		ResponseTypes:           []string{"code"},
		Scopes:                  "openid profile email offline_access",
		ClientType:              "public",
		TokenEndpointAuthMethod: "none",
	}); err != nil {
		log.Printf("warning: failed to seed admin client: %v", err)
	}
}

// seedAccountClient creates the autentico-account OAuth2 client if it does not already exist.
func seedAccountClient() {
	const accountClientName = "Autentico Account UI"
	if existing, err := client.ClientByClientID(config.AccountClientID); err == nil && existing != nil {
		return
	}
	baseURL := config.GetBootstrap().AppURL
	redirectURI := baseURL + "/account/callback"
	postLogoutURI := baseURL + "/account/"
	ssoTimeout := "24h"

	if _, err := client.CreateClientWithID(config.AccountClientID, client.ClientCreateRequest{
		ClientName:              accountClientName,
		RedirectURIs:            []string{redirectURI},
		PostLogoutRedirectURIs:  []string{postLogoutURI},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		Scopes:                  "openid profile email offline_access",
		ClientType:              "public",
		TokenEndpointAuthMethod: "none",
		SsoSessionIdleTimeout:   &ssoTimeout,
	}); err != nil {
		log.Printf("warning: failed to seed account client: %v", err)
	}
}

func validateBootstrapSecrets(bs *config.BootstrapConfig) error {
	if bs.AuthAccessTokenSecret == "" || bs.AuthRefreshTokenSecret == "" || bs.AuthCSRFProtectionSecretKey == "" {
		return fmt.Errorf(
			"missing required secrets: AUTENTICO_ACCESS_TOKEN_SECRET, AUTENTICO_REFRESH_TOKEN_SECRET, " +
				"and AUTENTICO_CSRF_SECRET_KEY must all be set; " +
				"run 'autentico init' to generate a .env file with secure values, or set them manually",
		)
	}
	return nil
}
