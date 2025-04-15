package routes

import (
	"net/http"

	. "autentico/pkg/model"
	"autentico/pkg/utils"
)

func DummyRoute(w http.ResponseWriter, r *http.Request) {
	response := AuthErrorResponse{
		Error:            "not_implemented",
		ErrorDescription: "Not implemented",
	}
	utils.WriteApiResponse(w, response, http.StatusInternalServerError)
}
