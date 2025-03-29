package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"autentico/pkg/auth"
	"autentico/pkg/db"
)

// handler for creating a user
func createUserHandler(w http.ResponseWriter, r *http.Request) {
	var user auth.User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Create user
	err = auth.CreateUser(user.Username, user.Password, user.Email)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error creating user: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "User created successfully"})
}

// handler for logging in a user
func loginUserHandler(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	user, err := auth.LoginUser(creds.Username, creds.Password)
	if err != nil {
		http.Error(w, fmt.Sprintf("Login failed: %v", err), http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(user)
}

// handler for updating user email
func updateUserHandler(w http.ResponseWriter, r *http.Request) {
	var update struct {
		Username string `json:"username"`
		Email    string `json:"email"`
	}

	err := json.NewDecoder(r.Body).Decode(&update)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	err = auth.UpdateUser(update.Username, update.Email)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error updating user: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "User updated successfully"})
}

// handler for deleting a user
func deleteUserHandler(w http.ResponseWriter, r *http.Request) {
	var username struct {
		Username string `json:"username"`
	}

	err := json.NewDecoder(r.Body).Decode(&username)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	err = auth.DeleteUser(username.Username)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error deleting user: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "User deleted successfully"})
}

// handler for logging out a user
func logoutUserHandler(w http.ResponseWriter, r *http.Request) {
	// For stateless sessions, this is a no-op. It could be expanded with token invalidation.
	auth.LogoutUser()

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "User logged out successfully"})
}

func main() {
	// Initialize the database
	_, err := db.InitDB()
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	http.HandleFunc("/create", createUserHandler)
	http.HandleFunc("/login", loginUserHandler)
	http.HandleFunc("/update", updateUserHandler)
	http.HandleFunc("/delete", deleteUserHandler)
	http.HandleFunc("/logout", logoutUserHandler)

	port := "8080"
	log.Printf("Server started at http://localhost:%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))

	defer db.CloseDB()
}
