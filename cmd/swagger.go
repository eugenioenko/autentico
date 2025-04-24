package main

import (
	_ "autentico/docs"
	"autentico/pkg/config"
	"log"
	"net/http"

	httpSwagger "github.com/swaggo/http-swagger"
)

func main() {
	port := config.Get().SwaggerPort
	http.HandleFunc("/swagger/", httpSwagger.WrapHandler)
	log.Printf("Swagger server started at http://localhost:%s/swagger/index.html", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
