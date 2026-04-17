package account

import (
	"net/http"

	"github.com/eugenioenko/autentico/pkg/federation"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// HandleListConnectedProviders godoc
// @Summary List connected providers
// @Description Returns all external identity providers linked to the authenticated user's account.
// @Tags account-federation
// @Produce json
// @Security UserAuth
// @Success 200 {array} ConnectedProviderResponse
// @Failure 401 {object} model.ApiError
// @Router /account/api/connected-providers [get]
func HandleListConnectedProviders(w http.ResponseWriter, r *http.Request) {
	usr, err := user.GetUserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	identities, err := federation.FederatedIdentitiesByUserID(usr.ID)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	var response []ConnectedProviderResponse
	for _, fi := range identities {
		providerName := fi.ProviderID
		if provider, err := federation.FederationProviderByID(fi.ProviderID); err == nil {
			providerName = provider.Name
		}
		email := ""
		if fi.Email.Valid {
			email = fi.Email.String
		}
		response = append(response, ConnectedProviderResponse{
			ID:           fi.ID,
			ProviderID:   fi.ProviderID,
			ProviderName: providerName,
			Email:        email,
			CreatedAt:    fi.CreatedAt,
		})
	}

	utils.SuccessResponse(w, response, http.StatusOK)
}

// HandleDisconnectProvider godoc
// @Summary Disconnect a provider
// @Description Removes a linked external identity provider. Cannot disconnect the only login method.
// @Tags account-federation
// @Produce json
// @Param id path string true "Federated identity ID"
// @Security UserAuth
// @Success 200 {object} map[string]string
// @Failure 400 {object} model.ApiError
// @Failure 401 {object} model.ApiError
// @Failure 403 {object} model.ApiError
// @Router /account/api/connected-providers/{id} [delete]
func HandleDisconnectProvider(w http.ResponseWriter, r *http.Request) {
	usr, err := user.GetUserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	identityID := r.PathValue("id")
	if identityID == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing identity ID")
		return
	}

	identities, err := federation.FederatedIdentitiesByUserID(usr.ID)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	// Verify ownership
	var target *federation.FederatedIdentity
	for _, fi := range identities {
		if fi.ID == identityID {
			fi := fi
			target = fi
			break
		}
	}
	if target == nil {
		utils.WriteErrorResponse(w, http.StatusForbidden, "forbidden", "Identity not found or not owned by you")
		return
	}

	// Prevent lockout: user must have either a password or another federated identity
	if usr.Password == "" && len(identities) <= 1 {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "lockout_prevention", "Cannot disconnect your only login method")
		return
	}

	if err := federation.DeleteFederatedIdentity(identityID); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	utils.SuccessResponse(w, map[string]string{"message": "Provider disconnected"}, http.StatusOK)
}
