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
	_, err := db.InitDB()
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.CloseDB()

	basePath := config.AppBasePath
	mux := http.NewServeMux()

	mux.HandleFunc(basePath+"/users/create", routes.CreateUser)
	mux.HandleFunc(basePath+"/users/login", routes.LoginUser)
	mux.HandleFunc(basePath+"/users/update", routes.UpdateUser)
	mux.HandleFunc(basePath+"/users/delete", routes.DeleteUser)
	//http.HandleFunc("/logout", logoutUser)

	port := config.AppPort
	log.Printf("Auth server started at http://localhost:%s%s", port, basePath)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}
