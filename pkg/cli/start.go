package cli

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/urfave/cli/v2"

	"github.com/eugenioenko/autentico/pkg/admin"
	"github.com/eugenioenko/autentico/pkg/appsettings"
	"github.com/eugenioenko/autentico/pkg/authorize"
	"github.com/eugenioenko/autentico/pkg/cleanup"
	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/federation"
	"github.com/eugenioenko/autentico/pkg/introspect"
	"github.com/eugenioenko/autentico/pkg/key"
	"github.com/eugenioenko/autentico/pkg/login"
	"github.com/eugenioenko/autentico/pkg/mfa"
	"github.com/eugenioenko/autentico/pkg/middleware"
	"github.com/eugenioenko/autentico/pkg/ratelimit"
	"github.com/eugenioenko/autentico/pkg/onboarding"
	"github.com/eugenioenko/autentico/pkg/passkey"
	"github.com/eugenioenko/autentico/pkg/session"
	"github.com/eugenioenko/autentico/pkg/signup"
	"github.com/eugenioenko/autentico/pkg/token"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/userinfo"
	"github.com/eugenioenko/autentico/pkg/wellknown"
	_ "github.com/eugenioenko/autentico/docs"
	httpSwagger "github.com/swaggo/http-swagger"
)

func RunStart(_ *cli.Context) error {
	config.InitBootstrap()

	bs := config.GetBootstrap()
	if _, err := db.InitDB(bs.DbFilePath); err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}
	defer db.CloseDB()

	// Load soft settings from DB into config.Values, writing defaults for any missing keys
	if err := appsettings.EnsureDefaults(); err != nil {
		log.Printf("warning: could not ensure settings defaults: %v", err)
	}
	if err := appsettings.LoadIntoConfig(); err != nil {
		log.Printf("warning: could not load settings from DB: %v", err)
	}

	// Initialize RSA key (from env var or ephemeral with warning)
	key.GetPrivateKey()

	// Auto-seed admin UI client if not present
	seedAdminClient()

	cfg := config.Get()
	oauth := bs.AppOAuthPath
	mux := http.NewServeMux()

	// Per-IP rate limiter for authentication endpoints (rps=0 disables)
	limiterStore := ratelimit.NewStore(bs.RateLimitRPS, bs.RateLimitBurst, bs.RateLimitRPM, bs.RateLimitRPMBurst)
	rateLimited := middleware.RateLimitMiddleware(limiterStore)

	mux.HandleFunc("/user", user.HandleCreateUser)
	mux.HandleFunc("/.well-known/openid-configuration", wellknown.HandleWellKnownConfig)
	mux.HandleFunc(oauth+"/.well-known/openid-configuration", wellknown.HandleWellKnownConfig)
	mux.HandleFunc("/.well-known/jwks.json", wellknown.HandleJWKS)
	mux.Handle(oauth+"/authorize", middleware.CSRFMiddleware(http.HandlerFunc(authorize.HandleAuthorize)))
	mux.Handle(oauth+"/authorize/", middleware.CSRFMiddleware(http.HandlerFunc(authorize.HandleAuthorize)))
	mux.Handle(oauth+"/login", rateLimited(middleware.CSRFMiddleware(http.HandlerFunc(login.HandleLoginUser))))
	mux.Handle(oauth+"/login/", rateLimited(middleware.CSRFMiddleware(http.HandlerFunc(login.HandleLoginUser))))
	mux.Handle(oauth+"/signup", middleware.CSRFMiddleware(http.HandlerFunc(signup.HandleSignup)))
	mux.Handle(oauth+"/signup/", middleware.CSRFMiddleware(http.HandlerFunc(signup.HandleSignup)))
	mux.Handle(oauth+"/onboard", middleware.CSRFMiddleware(http.HandlerFunc(onboarding.HandleOnboard)))
	mux.Handle(oauth+"/onboard/", middleware.CSRFMiddleware(http.HandlerFunc(onboarding.HandleOnboard)))
	mux.Handle(oauth+"/mfa", rateLimited(middleware.CSRFMiddleware(http.HandlerFunc(mfa.HandleMfa))))
	mux.Handle(oauth+"/mfa/", rateLimited(middleware.CSRFMiddleware(http.HandlerFunc(mfa.HandleMfa))))
	mux.HandleFunc("GET "+oauth+"/passkey/login/begin", passkey.HandleLoginBegin)
	mux.Handle("POST "+oauth+"/passkey/login/finish", rateLimited(http.HandlerFunc(passkey.HandleLoginFinish)))
	mux.HandleFunc("POST "+oauth+"/passkey/register/finish", passkey.HandleRegisterFinish)
	mux.HandleFunc("GET "+oauth+"/federation/{id}", federation.HandleFederationBegin)
	mux.HandleFunc("GET "+oauth+"/federation/{id}/callback", federation.HandleFederationCallback)
	mux.Handle(oauth+"/token", rateLimited(http.HandlerFunc(token.HandleToken)))
	mux.Handle(oauth+"/protocol/openid-connect/token", rateLimited(http.HandlerFunc(token.HandleToken)))
	mux.HandleFunc(oauth+"/revoke", token.HandleRevoke)
	mux.HandleFunc(oauth+"/userinfo", userinfo.HandleUserInfo)
	mux.HandleFunc(oauth+"/protocol/openid-connect/userinfo", userinfo.HandleUserInfo)
	mux.HandleFunc(oauth+"/logout", session.HandleLogout)
	mux.HandleFunc(oauth+"/introspect", introspect.HandleIntrospect)
	mux.Handle("/swagger/", httpSwagger.WrapHandler)

	// Client registration endpoints (admin only)
	mux.Handle(oauth+"/register", middleware.AdminAuthMiddleware(http.HandlerFunc(client.HandleClientEndpoint)))
	mux.Handle(oauth+"/register/", middleware.AdminAuthMiddleware(http.HandlerFunc(client.HandleClientEndpoint)))

	// Admin API endpoints
	mux.Handle("/admin/api/federation", middleware.AdminAuthMiddleware(http.HandlerFunc(federation.HandleAdminFederationEndpoint)))
	mux.Handle("/admin/api/federation/", middleware.AdminAuthMiddleware(http.HandlerFunc(federation.HandleAdminFederationEndpoint)))
	mux.Handle("/admin/api/users", middleware.AdminAuthMiddleware(http.HandlerFunc(user.HandleUserAdminEndpoint)))
	mux.Handle("/admin/api/users/unlock", middleware.AdminAuthMiddleware(http.HandlerFunc(user.HandleUnlockUser)))
	mux.Handle("/admin/api/clients", middleware.AdminAuthMiddleware(http.HandlerFunc(client.HandleClientEndpoint)))
	mux.Handle("/admin/api/clients/", middleware.AdminAuthMiddleware(http.HandlerFunc(client.HandleClientEndpoint)))
	mux.Handle("/admin/api/sessions", middleware.AdminAuthMiddleware(http.HandlerFunc(session.HandleSessionAdminEndpoint)))
	mux.Handle("/admin/api/stats", middleware.AdminAuthMiddleware(http.HandlerFunc(admin.HandleStats)))
	mux.Handle("/admin/api/settings", middleware.AdminAuthMiddleware(http.HandlerFunc(appsettings.HandleSettings)))
	mux.HandleFunc("/admin/api/onboarding", appsettings.HandleOnboarding)

	// Admin UI & Docs
	mux.Handle("/admin/", admin.Handler())

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cleanup.Start(ctx, cfg.CleanupInterval, cfg.CleanupRetention, func() {
		limiterStore.Cleanup(10 * time.Minute)
	})

	baseURL := bs.AppURL
	fmt.Println()
	fmt.Println("  Autentico OIDC Identity Provider")
	fmt.Println()

	if !appsettings.IsOnboarded() {
		fmt.Printf("  ONBOARDING: %s/admin/\n", baseURL)
		fmt.Println()
	}

	fmt.Printf("  Server:    %s\n", baseURL)
	fmt.Printf("  Admin UI:  %s/admin/\n", baseURL)
	fmt.Printf("  API Docs:  %s/admin/docs/\n", baseURL)
	fmt.Printf("  Swagger:   %s/swagger/index.html\n", baseURL)
	fmt.Printf("  WellKnown: %s/.well-known/openid-configuration\n", baseURL)
	fmt.Printf("  JWKS:      %s/.well-known/jwks.json\n", baseURL)
	fmt.Printf("  Authorize: %s%s/authorize\n", baseURL, oauth)
	fmt.Printf("  Token:     %s%s/token\n", baseURL, oauth)
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
	if err := client.CreateClientWithID(adminClientID, client.ClientCreateRequest{
		ClientName:              adminClientName,
		RedirectURIs:            []string{redirectURI},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		ClientType:              "public",
		TokenEndpointAuthMethod: "none",
	}); err != nil {
		log.Printf("warning: failed to seed admin client: %v", err)
	}
}
