package main

import (
	"log"
	"net/http"

	"github.com/eugenioenko/autentico/pkg/authorize"
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
// @host localhost:8080
// @BasePath /

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
	middlewareList := []func(http.Handler) http.Handler{
		middleware.LoggingMiddleware,
	}
	if config.Get().AppEnableCORS {
		middlewareList = append(middlewareList, middleware.CORSMiddleware)
	}
	combinedMiddleware := middleware.CombineMiddlewares(middlewareList)
	log.Fatal(http.ListenAndServe(":"+port, combinedMiddleware(mux)))
}
