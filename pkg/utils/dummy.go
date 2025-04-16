package utils

import (
	"net/http"

	"autentico/pkg/model"
)

func DummyRoute(w http.ResponseWriter, r *http.Request) {
	response := model.AuthErrorResponse{
		Error:            "not_implemented",
		ErrorDescription: "Not implemented",
	}
	WriteApiResponse(w, response, http.StatusInternalServerError)
}
