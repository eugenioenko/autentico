package main

import (
	"log"
	"net/http"

	"autentico/pkg/authorize"
	"autentico/pkg/config"
	"autentico/pkg/db"
	"autentico/pkg/introspect"
	"autentico/pkg/login"
	"autentico/pkg/middleware"
	"autentico/pkg/session"
	"autentico/pkg/token"
	"autentico/pkg/user"
	"autentico/pkg/userinfo"
	"autentico/pkg/wellknown"
)

// @title Autentico OIDC
// @version 1.0
// @description Authentication and ABAC Authorization Service
// @host localhost:8080
// @BasePath /oauth2

func main() {
	_, err := db.InitDB(config.Get().DbFilePath)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.CloseDB()

	oauth := config.Get().AppOAuthPath
	mux := http.NewServeMux()

	mux.HandleFunc("/users/create", user.HandleCreateUser)
	mux.HandleFunc("/.well-known/openid-configuration", wellknown.HandleWellKnownConfig)
	mux.Handle(oauth+"/authorize", middleware.CSRFMiddleware(http.HandlerFunc(authorize.HandleAuthorize)))
	mux.Handle(oauth+"/login", middleware.CSRFMiddleware(http.HandlerFunc(login.HandleLoginUser)))
	mux.HandleFunc(oauth+"/token", token.HandleToken)
	mux.HandleFunc(oauth+"/revoke", token.HandleRevoke)
	mux.HandleFunc(oauth+"/userinfo", userinfo.HandleUserInfo)
	mux.HandleFunc(oauth+"/logout", session.HandleLogout)
	mux.HandleFunc(oauth+"/introspect", introspect.HandleIntrospect)

	port := config.Get().AppPort
	log.Printf("Autentico started at http://localhost:%s", port)
	loggingMux := middleware.LoggingMiddleware(mux)
	log.Fatal(http.ListenAndServe(":"+port, loggingMux))
}
