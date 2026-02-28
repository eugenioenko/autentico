package cli

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/urfave/cli/v2"

	"github.com/eugenioenko/autentico/pkg/admin"
	"github.com/eugenioenko/autentico/pkg/authorize"
	"github.com/eugenioenko/autentico/pkg/cleanup"
	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/introspect"
	"github.com/eugenioenko/autentico/pkg/login"
	"github.com/eugenioenko/autentico/pkg/mfa"
	"github.com/eugenioenko/autentico/pkg/middleware"
	"github.com/eugenioenko/autentico/pkg/passkey"
	"github.com/eugenioenko/autentico/pkg/session"
	"github.com/eugenioenko/autentico/pkg/signup"
	"github.com/eugenioenko/autentico/pkg/token"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/userinfo"
	"github.com/eugenioenko/autentico/pkg/wellknown"
)

func RunStart(c *cli.Context) error {
	if err := config.InitConfig("autentico.json"); err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	cfg := config.Get()
	if _, err := db.InitDB(cfg.DbFilePath); err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}
	defer db.CloseDB()

	oauth := cfg.AppOAuthPath
	mux := http.NewServeMux()

	mux.HandleFunc("/user", user.HandleCreateUser)
	mux.HandleFunc("/.well-known/openid-configuration", wellknown.HandleWellKnownConfig)
	mux.HandleFunc(oauth+"/.well-known/openid-configuration", wellknown.HandleWellKnownConfig)
	mux.HandleFunc("/.well-known/jwks.json", wellknown.HandleJWKS)
	mux.Handle(oauth+"/authorize", middleware.CSRFMiddleware(http.HandlerFunc(authorize.HandleAuthorize)))
	mux.Handle(oauth+"/login", middleware.CSRFMiddleware(http.HandlerFunc(login.HandleLoginUser)))
	mux.Handle(oauth+"/signup", middleware.CSRFMiddleware(http.HandlerFunc(signup.HandleSignup)))
	mux.Handle(oauth+"/mfa", middleware.CSRFMiddleware(http.HandlerFunc(mfa.HandleMfa)))
	mux.HandleFunc("GET "+oauth+"/passkey/login/begin", passkey.HandleLoginBegin)
	mux.HandleFunc("POST "+oauth+"/passkey/login/finish", passkey.HandleLoginFinish)
	mux.HandleFunc("POST "+oauth+"/passkey/register/finish", passkey.HandleRegisterFinish)
	mux.HandleFunc(oauth+"/token", token.HandleToken)
	mux.HandleFunc(oauth+"/protocol/openid-connect/token", token.HandleToken)
	mux.HandleFunc(oauth+"/revoke", token.HandleRevoke)
	mux.HandleFunc(oauth+"/userinfo", userinfo.HandleUserInfo)
	mux.HandleFunc(oauth+"/protocol/openid-connect/userinfo", userinfo.HandleUserInfo)
	mux.HandleFunc(oauth+"/logout", session.HandleLogout)
	mux.HandleFunc(oauth+"/introspect", introspect.HandleIntrospect)

	// Client registration endpoints (admin only)
	mux.Handle(oauth+"/register", middleware.AdminAuthMiddleware(http.HandlerFunc(client.HandleClientEndpoint)))
	mux.Handle(oauth+"/register/", middleware.AdminAuthMiddleware(http.HandlerFunc(client.HandleClientEndpoint)))

	// Admin API endpoints
	mux.Handle("/admin/api/users", middleware.AdminAuthMiddleware(http.HandlerFunc(user.HandleUserAdminEndpoint)))
	mux.Handle("/admin/api/users/unlock", middleware.AdminAuthMiddleware(http.HandlerFunc(user.HandleUnlockUser)))
	mux.Handle("/admin/api/clients", middleware.AdminAuthMiddleware(http.HandlerFunc(client.HandleClientEndpoint)))
	mux.Handle("/admin/api/clients/", middleware.AdminAuthMiddleware(http.HandlerFunc(client.HandleClientEndpoint)))
	mux.Handle("/admin/api/sessions", middleware.AdminAuthMiddleware(http.HandlerFunc(session.HandleSessionAdminEndpoint)))
	mux.Handle("/admin/api/stats", middleware.AdminAuthMiddleware(http.HandlerFunc(admin.HandleStats)))

	// Admin UI
	mux.Handle("/admin/", admin.Handler())

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cleanup.Start(ctx, cfg.CleanupInterval, cfg.CleanupRetention)

	port := cfg.AppPort
	baseURL := fmt.Sprintf("http://localhost:%s", port)
	fmt.Println()
	fmt.Println("  Autentico OIDC Identity Provider")
	fmt.Println()
	fmt.Printf("  Server:    %s\n", baseURL)
	fmt.Printf("  Admin UI:  %s/admin/\n", baseURL)
	fmt.Printf("  WellKnown: %s/.well-known/openid-configuration\n", baseURL)
	fmt.Printf("  JWKS:      %s/.well-known/jwks.json\n", baseURL)
	fmt.Printf("  Authorize: %s%s/authorize\n", baseURL, oauth)
	fmt.Printf("  Token:     %s%s/token\n", baseURL, oauth)
	fmt.Println()
	middlewareList := []func(http.Handler) http.Handler{
		middleware.LoggingMiddleware,
	}
	if cfg.AppEnableCORS {
		middlewareList = append(middlewareList, middleware.CORSMiddleware)
	}
	combinedMiddleware := middleware.CombineMiddlewares(middlewareList)

	srv := &http.Server{
		Addr:    ":" + port,
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
