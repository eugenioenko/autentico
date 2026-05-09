package token

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/eugenioenko/autentico/pkg/devicecode"
	"github.com/eugenioenko/autentico/pkg/reqid"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// handleDeviceCodeGrant implements the token polling side of RFC 8628 §3.4-3.5.
func handleDeviceCodeGrant(w http.ResponseWriter, r *http.Request, request TokenRequest) (*user.User, string, error) {
	if request.DeviceCode == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "device_code is required")
		return nil, "", errGrantHandled
	}

	dc, err := devicecode.DeviceCodeByCode(request.DeviceCode)
	if err != nil {
		slog.Warn("token: device_code not found", "request_id", reqid.Get(r.Context()))
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_grant", "Invalid device_code")
		return nil, "", errGrantHandled
	}

	// RFC 8628 §3.5: expired_token
	if time.Now().After(dc.ExpiresAt) {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "expired_token", "The device code has expired")
		return nil, "", errGrantHandled
	}

	// RFC 8628 §3.5: slow_down — enforce polling interval
	if dc.LastPolledAt != nil {
		elapsed := time.Since(*dc.LastPolledAt)
		if elapsed < time.Duration(dc.IntervalSeconds)*time.Second {
			// RFC 8628 §3.5: slow_down adds 5 seconds to the interval
			_ = devicecode.UpdateLastPolledAt(dc.Code, time.Now())
			utils.WriteErrorResponse(w, http.StatusBadRequest, "slow_down", "Polling too frequently")
			return nil, "", errGrantHandled
		}
	}
	_ = devicecode.UpdateLastPolledAt(dc.Code, time.Now())

	switch dc.Status {
	case "pending":
		// RFC 8628 §3.5: authorization_pending
		utils.WriteErrorResponse(w, http.StatusBadRequest, "authorization_pending", "The user has not yet authorized this device")
		return nil, "", errGrantHandled
	case "denied":
		// RFC 8628 §3.5: access_denied
		utils.WriteErrorResponse(w, http.StatusBadRequest, "access_denied", "The user denied the authorization request")
		return nil, "", errGrantHandled
	case "authorized":
		if dc.UserID == nil {
			utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Device code authorized but no user associated")
			return nil, "", errGrantHandled
		}
		usr, err := user.UserByID(*dc.UserID)
		if err != nil {
			slog.Error("token: device_code user not found", "request_id", reqid.Get(r.Context()), "user_id", *dc.UserID)
			utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_grant", "User not found")
			return nil, "", errGrantHandled
		}
		return usr, dc.Scope, nil
	default:
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_grant", "Invalid device code status")
		return nil, "", errGrantHandled
	}
}

// errGrantHandled is a sentinel error indicating the grant handler already wrote an HTTP response.
var errGrantHandled = &grantError{}

type grantError struct{}

func (e *grantError) Error() string { return "grant handled" }
