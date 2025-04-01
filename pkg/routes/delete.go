package routes

import (
	"autentico/pkg/users"
	"encoding/json"
	"fmt"
	"net/http"
)

func DeleteUser(w http.ResponseWriter, r *http.Request) {
	var username struct {
		Username string `json:"username"`
	}

	err := json.NewDecoder(r.Body).Decode(&username)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	err = users.DeleteUser(username.Username)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error deleting user: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "User deleted successfully"})
}
