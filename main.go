package main

import (
	"encoding/json"
	"log"
	"net/http"

	"autentico/pkg/config"
	"autentico/pkg/db"
	"autentico/pkg/routes"
)

// handler for logging out a user
func logoutUser(w http.ResponseWriter, r *http.Request) {

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "User logged out successfully"})
}

func main() {
	_, err := db.InitDB()
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.CloseDB()

	http.HandleFunc("/create", routes.CreateUser)
	http.HandleFunc("/login", routes.LoginUser)
	http.HandleFunc("/update", routes.UpdateUser)
	http.HandleFunc("/delete", routes.DeleteUser)
	//http.HandleFunc("/logout", logoutUser)

	port := config.AppPort
	log.Printf("Auth server started at localhost:%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
