package routes

import (
	"encoding/json"
	"fmt"
	"net/http"

	"autentico/pkg/user"
)

func UpdateUser(w http.ResponseWriter, r *http.Request) {
	var update struct {
		Username string `json:"username"`
		Email    string `json:"email"`
	}

	err := json.NewDecoder(r.Body).Decode(&update)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)

		return
	}

	err = user.UpdateUser(update.Username, update.Email)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error updating user: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "User updated successfully"})
}
