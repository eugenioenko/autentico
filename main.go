package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/eugenioenko/autentico/pkg/admin"
	"github.com/eugenioenko/autentico/pkg/authorize"
	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/introspect"
	"github.com/eugenioenko/autentico/pkg/login"
	"github.com/eugenioenko/autentico/pkg/middleware"
	"github.com/eugenioenko/autentico/pkg/session"
	"github.com/eugenioenko/autentico/pkg/token"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/userinfo"
	"github.com/eugenioenko/autentico/pkg/wellknown"
)

// @title Autentico OIDC
// @version 1.0
// @description Authentication Service
// @host localhost:9999
// @BasePath /

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "create-admin" {
		createAdmin(os.Args[2:])
		return
	}

	if len(os.Args) >= 2 && os.Args[1] == "create-admin-client" {
		createAdminClient()
		return
	}

	if err := config.InitConfig("autentico.json"); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	_, err := db.InitDB(config.Get().DbFilePath)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.CloseDB()

	oauth := config.Get().AppOAuthPath
	mux := http.NewServeMux()

	mux.HandleFunc("/user", user.HandleCreateUser)
	mux.HandleFunc("/.well-known/openid-configuration", wellknown.HandleWellKnownConfig)
	mux.HandleFunc(oauth+"/.well-known/openid-configuration", wellknown.HandleWellKnownConfig)
	mux.HandleFunc("/.well-known/jwks.json", wellknown.HandleJWKS)
	mux.Handle(oauth+"/authorize", middleware.CSRFMiddleware(http.HandlerFunc(authorize.HandleAuthorize)))
	mux.Handle(oauth+"/login", middleware.CSRFMiddleware(http.HandlerFunc(login.HandleLoginUser)))
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

	// Admin UI
	mux.Handle("/admin/", admin.Handler())

	port := config.Get().AppPort
	log.Printf("Autentico started at http://localhost:%s", port)
	middlewareList := []func(http.Handler) http.Handler{
		middleware.LoggingMiddleware,
	}
	if config.Get().AppEnableCORS {
		middlewareList = append(middlewareList, middleware.CORSMiddleware)
	}
	combinedMiddleware := middleware.CombineMiddlewares(middlewareList)
	log.Fatal(http.ListenAndServe(":"+port, combinedMiddleware(mux)))
}

func createAdmin(args []string) {
	fs := flag.NewFlagSet("create-admin", flag.ExitOnError)
	email := fs.String("email", "", "Admin email address (required)")
	password := fs.String("password", "", "Admin password (required)")

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if *email == "" || *password == "" {
		fmt.Fprintln(os.Stderr, "Usage: autentico create-admin --email=<email> --password=<password>")
		os.Exit(1)
	}

	if err := config.InitConfig("autentico.json"); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	cfg := config.Get()
	if len(*password) < cfg.ValidationMinPasswordLength {
		fmt.Fprintf(os.Stderr, "Error: password must be at least %d characters\n", cfg.ValidationMinPasswordLength)
		os.Exit(1)
	}

	if _, err := db.InitDB(cfg.DbFilePath); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.CloseDB()

	resp, err := user.CreateUser(*email, *password, *email)
	if err != nil {
		log.Fatalf("Failed to create user: %v", err)
	}

	if err := user.UpdateUser(resp.ID, *email, "admin"); err != nil {
		log.Fatalf("Failed to set admin role: %v", err)
	}

	fmt.Printf("Admin user created successfully (ID: %s)\n", resp.ID)
}

func createAdminClient() {
	if err := config.InitConfig("autentico.json"); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	cfg := config.Get()
	if _, err := db.InitDB(cfg.DbFilePath); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.CloseDB()

	const adminClientName = "Autentico Admin UI"
	const adminClientID = "autentico-admin"

	// Check if admin client already exists
	existing, err := client.ClientByName(adminClientName)
	if err == nil && existing != nil {
		fmt.Printf("Admin UI client already exists (client_id: %s)\n", existing.ClientID)
		return
	}

	redirectURI := cfg.AppURL + "/admin/callback"
	err = client.CreateClientWithID(adminClientID, client.ClientCreateRequest{
		ClientName:              adminClientName,
		RedirectURIs:            []string{redirectURI},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		ClientType:              "public",
		TokenEndpointAuthMethod: "none",
	})
	if err != nil {
		log.Fatalf("Failed to create admin client: %v", err)
	}

	fmt.Printf("Admin UI client created successfully\n")
	fmt.Printf("  client_id:    %s\n", adminClientID)
	fmt.Printf("  redirect_uri: %s\n", redirectURI)
}
