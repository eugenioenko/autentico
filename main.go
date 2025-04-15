package main

import (
	"log"
	"net/http"

	"autentico/pkg/config"
	"autentico/pkg/db"
	"autentico/pkg/routes"
)

// @title Autentico Microservice API
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

	mux.HandleFunc(oauth+"/users/create", routes.CreateUser)
	mux.HandleFunc(oauth+"/users/login", routes.LoginUser)
	mux.HandleFunc(oauth+"/users/update", routes.UpdateUser)
	mux.HandleFunc(oauth+"/users/delete", routes.DeleteUser)

	mux.HandleFunc("/.well-known/openid-configuration", routes.WellKnownConfig)
	mux.HandleFunc("/.well-known/jwks.json", routes.WellKnownConfig)
	mux.HandleFunc(oauth+"/authorize", routes.DummyRoute)
	mux.HandleFunc(oauth+"/token", routes.DummyRoute)
	mux.HandleFunc(oauth+"/userinfo", routes.DummyRoute)
	mux.HandleFunc(oauth+"/logout", routes.DummyRoute)
	mux.HandleFunc(oauth+"/introspect", routes.DummyRoute)

	port := config.Get().AppPort
	log.Printf("Auth server started at http://localhost:%s", port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}
