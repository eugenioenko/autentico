package cli

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/urfave/cli/v2"

	"github.com/eugenioenko/autentico/docs"
	"github.com/eugenioenko/autentico/pkg/account"
	"github.com/eugenioenko/autentico/pkg/admin"
	"github.com/eugenioenko/autentico/pkg/authui"
	"github.com/eugenioenko/autentico/pkg/deletion"
	"github.com/eugenioenko/autentico/pkg/appsettings"
	"github.com/eugenioenko/autentico/pkg/authorize"
	"github.com/eugenioenko/autentico/pkg/cleanup"
	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/db/migrations"
	"github.com/eugenioenko/autentico/pkg/emailverification"
	"github.com/eugenioenko/autentico/pkg/federation"
	"github.com/eugenioenko/autentico/pkg/health"
	"github.com/eugenioenko/autentico/pkg/introspect"
	"github.com/eugenioenko/autentico/pkg/key"
	"github.com/eugenioenko/autentico/pkg/login"
	"github.com/eugenioenko/autentico/pkg/mfa"
	"github.com/eugenioenko/autentico/pkg/middleware"
	"github.com/eugenioenko/autentico/pkg/onboarding"
	"github.com/eugenioenko/autentico/pkg/passkey"
	"github.com/eugenioenko/autentico/pkg/ratelimit"
	"github.com/eugenioenko/autentico/pkg/session"
	"github.com/eugenioenko/autentico/pkg/signup"
	"github.com/eugenioenko/autentico/pkg/token"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/userinfo"
	"github.com/eugenioenko/autentico/pkg/wellknown"
	httpSwagger "github.com/swaggo/http-swagger"
)

func RunStart(c *cli.Context) error {
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
		return fmt.Errorf("failed to initialize database: %w", err)
	}
	defer db.CloseDB()

	if c.Bool("auto-migrate") {
		if err := migrations.Run(db.GetDB(), true); err != nil {
			return err
		}
	} else if err := migrations.Check(db.GetDB()); err != nil {
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
	seedAdminClient()
	seedAccountClient()

	cfg := config.Get()
	oauth := bs.AppOAuthPath
	mux := http.NewServeMux()

	// Per-IP rate limiter for authentication endpoints (rps=0 disables)
	limiterStore := ratelimit.NewStore(bs.RateLimitRPS, bs.RateLimitBurst, bs.RateLimitRPM, bs.RateLimitRPMBurst)
	rateLimited := middleware.RateLimitMiddleware(limiterStore)
	rateLimitedFunc := func(h http.HandlerFunc) http.Handler { return rateLimited(h) }
	adminAPI := func(h http.HandlerFunc) http.Handler { return middleware.AdminAuthMiddleware(h) }
	csrfProtected := func(h http.HandlerFunc) http.Handler { return middleware.CSRFMiddleware(h) }

	// -------------------------------------------------------------------------
	// Infrastructure
	// -------------------------------------------------------------------------
	mux.HandleFunc("GET /healthz", health.HandleHealth)
	mux.Handle("/swagger/", httpSwagger.WrapHandler)

	// -------------------------------------------------------------------------
	// OIDC discovery (public, no auth)
	// -------------------------------------------------------------------------
	mux.HandleFunc("GET /.well-known/openid-configuration", wellknown.HandleWellKnownConfig)
	mux.HandleFunc("GET "+oauth+"/.well-known/openid-configuration", wellknown.HandleWellKnownConfig)
	mux.HandleFunc("GET /.well-known/jwks.json", wellknown.HandleJWKS)

	// -------------------------------------------------------------------------
	// OAuth2 / OIDC protocol endpoints
	// -------------------------------------------------------------------------

	mux.Handle("GET "+oauth+"/authorize", csrfProtected(authorize.HandleAuthorize))
	mux.Handle("POST "+oauth+"/authorize", http.HandlerFunc(authorize.HandleAuthorize))
	mux.Handle("POST "+oauth+"/login", rateLimited(csrfProtected(login.HandleLoginUser)))
	mux.Handle(oauth+"/mfa", rateLimited(csrfProtected(mfa.HandleMfa)))
	mux.Handle(oauth+"/mfa/", rateLimited(csrfProtected(mfa.HandleMfa)))
	mux.Handle("GET "+oauth+"/passkey/login/begin", rateLimitedFunc(passkey.HandleLoginBegin))
	mux.Handle("POST "+oauth+"/passkey/login/finish", rateLimitedFunc(passkey.HandleLoginFinish))
	mux.HandleFunc("GET "+oauth+"/passkey/register/begin", passkey.HandleRegisterBegin)
	mux.HandleFunc("POST "+oauth+"/passkey/register/finish", passkey.HandleRegisterFinish)
	mux.Handle("GET "+oauth+"/verify-email", csrfProtected(emailverification.HandleVerifyEmail))
	mux.Handle("POST "+oauth+"/resend-verification", csrfProtected(emailverification.HandleResendVerification))
	mux.HandleFunc("GET "+oauth+"/federation/{id}", federation.HandleFederationBegin)
	mux.HandleFunc("GET "+oauth+"/federation/{id}/callback", federation.HandleFederationCallback)
	mux.Handle(oauth+"/signup", csrfProtected(signup.HandleSignup))
	mux.Handle(oauth+"/signup/", csrfProtected(signup.HandleSignup))
	mux.Handle("POST "+oauth+"/token", rateLimitedFunc(token.HandleToken))
	mux.Handle("POST "+oauth+"/protocol/openid-connect/token", rateLimitedFunc(token.HandleToken))
	mux.HandleFunc("POST "+oauth+"/revoke", token.HandleRevoke)
	mux.HandleFunc("POST "+oauth+"/introspect", introspect.HandleIntrospect)
	mux.HandleFunc(oauth+"/userinfo", userinfo.HandleUserInfo)
	mux.HandleFunc(oauth+"/protocol/openid-connect/userinfo", userinfo.HandleUserInfo)
	mux.HandleFunc("POST "+oauth+"/logout", session.HandleLogout)
	mux.Handle("GET "+oauth+"/register", adminAPI(client.HandleListClients))
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
	mux.Handle("POST /admin/api/users/{id}/unlock", adminAPI(user.HandleUnlockUser))
	mux.Handle("GET /admin/api/clients", adminAPI(client.HandleListClients))
	mux.Handle("POST /admin/api/clients", adminAPI(client.HandleRegister))
	mux.Handle("GET /admin/api/clients/{client_id}", adminAPI(client.HandleGetClient))
	mux.Handle("PUT /admin/api/clients/{client_id}", adminAPI(client.HandleUpdateClient))
	mux.Handle("DELETE /admin/api/clients/{client_id}", adminAPI(client.HandleDeleteClient))
	mux.Handle("GET /admin/api/sessions", adminAPI(session.HandleListSessions))
	mux.Handle("DELETE /admin/api/sessions/{id}", adminAPI(session.HandleDeactivateSession))
	mux.Handle("GET /admin/api/federation", adminAPI(federation.HandleListProviders))
	mux.Handle("POST /admin/api/federation", adminAPI(federation.HandleCreateProvider))
	mux.Handle("GET /admin/api/federation/{id}", adminAPI(federation.HandleGetProvider))
	mux.Handle("PUT /admin/api/federation/{id}", adminAPI(federation.HandleUpdateProvider))
	mux.Handle("DELETE /admin/api/federation/{id}", adminAPI(federation.HandleDeleteProvider))
	mux.Handle("GET /admin/api/stats", adminAPI(admin.HandleStats))
	mux.Handle("GET /admin/api/settings", adminAPI(appsettings.HandleGetSettings))
	mux.Handle("PUT /admin/api/settings", adminAPI(appsettings.HandlePutSettings))
	mux.Handle("POST /admin/api/settings/test-smtp", adminAPI(appsettings.HandleTestSmtp))
	mux.Handle("GET /admin/api/deletion-requests", adminAPI(deletion.HandleListDeletionRequests))
	mux.Handle("POST /admin/api/deletion-requests/{id}/approve", adminAPI(deletion.HandleApproveDeletionRequest))
	mux.Handle("DELETE /admin/api/deletion-requests/{id}", adminAPI(deletion.HandleAdminCancelDeletionRequest))

	// -------------------------------------------------------------------------
	// Account self-service API (bearer-token authenticated per handler)
	// -------------------------------------------------------------------------
	mux.HandleFunc("GET /account/api/profile", account.HandleGetProfile)
	mux.HandleFunc("PUT /account/api/profile", account.HandleUpdateProfile)
	mux.HandleFunc("POST /account/api/password", account.HandleUpdatePassword)
	mux.HandleFunc("GET /account/api/sessions", account.HandleListSessions)
	mux.HandleFunc("DELETE /account/api/sessions/{id}", account.HandleRevokeSession)
	mux.HandleFunc("GET /account/api/passkeys", account.HandleListPasskeys)
	mux.HandleFunc("DELETE /account/api/passkeys/{id}", account.HandleDeletePasskey)
	mux.HandleFunc("PATCH /account/api/passkeys/{id}", account.HandleRenamePasskey)
	mux.HandleFunc("POST /account/api/passkeys/register/begin", account.HandleAddPasskeyBegin)
	mux.HandleFunc("POST /account/api/passkeys/register/finish", account.HandleAddPasskeyFinish)
	mux.HandleFunc("GET /account/api/mfa", account.HandleGetMfaStatus)
	mux.HandleFunc("POST /account/api/mfa/totp/setup", account.HandleSetupTotp)
	mux.HandleFunc("POST /account/api/mfa/totp/verify", account.HandleVerifyTotp)
	mux.HandleFunc("DELETE /account/api/mfa/totp", account.HandleDeleteMfa)
	mux.HandleFunc("GET /account/api/trusted-devices", account.HandleListTrustedDevices)
	mux.HandleFunc("DELETE /account/api/trusted-devices/{id}", account.HandleRevokeTrustedDevice)
	mux.HandleFunc("GET /account/api/connected-providers", account.HandleListConnectedProviders)
	mux.HandleFunc("DELETE /account/api/connected-providers/{id}", account.HandleDisconnectProvider)
	mux.HandleFunc("GET /account/api/settings", account.HandleGetSettings)
	mux.HandleFunc("GET /account/api/deletion-request", deletion.HandleGetDeletionRequest)
	mux.HandleFunc("POST /account/api/deletion-request", deletion.HandleRequestDeletion)
	mux.HandleFunc("DELETE /account/api/deletion-request", deletion.HandleCancelDeletionRequest)

	// -------------------------------------------------------------------------
	// Embedded UIs
	// -------------------------------------------------------------------------
	mux.Handle("/admin/", admin.Handler())
	mux.Handle("/account/", account.Handler())
	mux.Handle("/auth/", authui.StaticHandler())

	// -------------------------------------------------------------------------
	// First-time onboarding (only if no users exist, otherwise redirect to login)
	// -------------------------------------------------------------------------
	mux.Handle("/onboard", csrfProtected(onboarding.HandleOnboardDirect))
	mux.Handle("/onboard/", csrfProtected(onboarding.HandleOnboardDirect))

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
	fmt.Printf("  Admin UI:   %s/admin\n", baseURL)
	fmt.Printf("  Account UI: %s/account/\n", baseURL)
	fmt.Println()
	fmt.Printf("  API Docs:   %s/admin/docs/\n", baseURL)
	fmt.Printf("  Swagger:    %s/swagger/index.html\n", baseURL)
	fmt.Printf("  Docs:       https://autentico.top\n")
	fmt.Println()
	fmt.Printf("  WellKnown:  %s/.well-known/openid-configuration\n", baseURL)
	fmt.Printf("  JWKS:       %s/.well-known/jwks.json\n", baseURL)
	fmt.Printf("  Authorize:  %s%s/authorize\n", baseURL, oauth)
	fmt.Printf("  Token:      %s%s/token\n", baseURL, oauth)
	fmt.Println()

	middlewareList := []func(http.Handler) http.Handler{
		middleware.RequestIDMiddleware,
		middleware.LoggingMiddleware,
	}
	if bs.AppEnableCORS {
		middlewareList = append(middlewareList, middleware.CORSMiddleware)
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
func seedAdminClient() {
	const adminClientID = "autentico-admin"
	const adminClientName = "Autentico Admin UI"
	if existing, err := client.ClientByClientID(adminClientID); err == nil && existing != nil {
		return
	}
	redirectURI := config.GetBootstrap().AppURL + "/admin/callback"
	if _, err := client.CreateClientWithID(adminClientID, client.ClientCreateRequest{
		ClientName:              adminClientName,
		RedirectURIs:            []string{redirectURI},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
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
	const clientID = "autentico-account"
	const clientName = "Autentico Account UI"
	if existing, err := client.ClientByClientID(clientID); err == nil && existing != nil {
		return
	}
	baseURL := config.GetBootstrap().AppURL
	redirectURI := baseURL + "/account/callback"
	postLogoutURI := baseURL + "/account/"
	ssoTimeout := "24h"

	if _, err := client.CreateClientWithID(clientID, client.ClientCreateRequest{
		ClientName:              clientName,
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
