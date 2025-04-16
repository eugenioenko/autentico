package main

import (
	"log"
	"net/http"

	"autentico/pkg/authorize"
	"autentico/pkg/config"
	"autentico/pkg/db"
	"autentico/pkg/introspect"
	"autentico/pkg/login"
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
	// mux.HandleFunc("/.well-known/jwks.json", routes.WellKnownConfig)
	mux.HandleFunc(oauth+"/authorize", authorize.HandleAuthorize)
	mux.HandleFunc(oauth+"/token", token.HandleToken)
	mux.HandleFunc(oauth+"/userinfo", utils.DummyRoute)
	mux.HandleFunc(oauth+"/login", login.HandleLoginUser)
	mux.HandleFunc(oauth+"/logout", utils.DummyRoute)
	mux.HandleFunc(oauth+"/introspect", introspect.HandleIntrospect)

	port := config.Get().AppPort
	log.Printf("Auth server started at http://localhost:%s", port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}
