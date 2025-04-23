package main

import (
	"fmt"
	"log"
	"net/http"

	"autentico/pkg/authorize"
	"autentico/pkg/config"
	"autentico/pkg/db"
	"autentico/pkg/introspect"
	"autentico/pkg/login"
	"autentico/pkg/middleware"
	"autentico/pkg/token"
	"autentico/pkg/user"
	"autentico/pkg/utils"
	"autentico/pkg/wellknown"
)

// @title Autentico OIDC Service
// @version 1.0
// @description Authentication and ABAC Authorization Microservice
// @host localhost:8080
// @BasePath /api/v1/

func inspectRequestMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Inspect the request here
		// For example, you can log the method and URL of the request
		fmt.Println("Inspecting request:")
		log.Printf("Method: %s, URL: %s", r.Method, r.URL)
		next.ServeHTTP(w, r)
	})
}

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
	mux.Handle("/oauth2/authorize", middleware.CSRFMiddleware(http.HandlerFunc(authorize.HandleAuthorize)))
	mux.Handle("/oauth2/login", middleware.CSRFMiddleware(http.HandlerFunc(login.HandleLoginUser)))
	mux.HandleFunc(oauth+"/token", token.HandleToken)
	mux.HandleFunc(oauth+"/userinfo", utils.DummyRoute)
	mux.HandleFunc(oauth+"/logout", utils.DummyRoute)
	mux.HandleFunc(oauth+"/introspect", introspect.HandleIntrospect)

	port := config.Get().AppPort
	log.Printf("Autentico started at http://localhost:%s", port)
	loggingMux := middleware.LoggingMiddleware(mux)
	log.Fatal(http.ListenAndServe(":"+port, loggingMux))
}
