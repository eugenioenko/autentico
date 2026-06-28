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
	// RFC 8628 §3.4: device_code is REQUIRED in the token request
	if request.DeviceCode == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "device_code 为必填项")
		return nil, "", errGrantHandled
	}

	dc, err := devicecode.DeviceCodeByCode(request.DeviceCode)
	if err != nil {
		slog.Warn("token: device_code not found", "request_id", reqid.Get(r.Context()))
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_grant", "无效的 device_code")
		return nil, "", errGrantHandled
	}

	// RFC 8628 §3.4: verify the device_code was issued to this client
	if dc.ClientID != request.ClientID {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_grant", "device_code 不是为此客户端签发的")
		return nil, "", errGrantHandled
	}

	// RFC 8628 §3.5: expired_token
	if time.Now().After(dc.ExpiresAt) {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "expired_token", "设备码已过期")
		return nil, "", errGrantHandled
	}

	// RFC 8628 §3.5: slow_down — enforce polling interval
	if dc.LastPolledAt != nil {
		elapsed := time.Since(*dc.LastPolledAt)
		if elapsed < time.Duration(dc.IntervalSeconds)*time.Second {
			// RFC 8628 §3.5: slow_down adds 5 seconds to the interval
			_ = devicecode.UpdateLastPolledAt(dc.Code, time.Now())
			_ = devicecode.IncrementInterval(dc.Code)
			utils.WriteErrorResponse(w, http.StatusBadRequest, "slow_down", "轮询过于频繁")
			return nil, "", errGrantHandled
		}
	}
	_ = devicecode.UpdateLastPolledAt(dc.Code, time.Now())

	switch dc.Status {
	case "pending":
		// RFC 8628 §3.5: authorization_pending
		utils.WriteErrorResponse(w, http.StatusBadRequest, "authorization_pending", "用户尚未授权此设备")
		return nil, "", errGrantHandled
	case "denied":
		// RFC 8628 §3.5: access_denied
		utils.WriteErrorResponse(w, http.StatusBadRequest, "access_denied", "用户拒绝了授权请求")
		return nil, "", errGrantHandled
	case "authorized":
		if dc.UserID == nil {
			utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "设备码已授权但无关联用户")
			return nil, "", errGrantHandled
		}
		usr, err := user.UserByID(*dc.UserID)
		if err != nil {
			slog.Error("token: device_code user not found", "request_id", reqid.Get(r.Context()), "user_id", *dc.UserID)
			utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_grant", "用户未找到")
			return nil, "", errGrantHandled
		}
		// RFC 8628 §3.5: device code is single-use; mark consumed to prevent replay
		_ = devicecode.ConsumeDeviceCode(dc.Code)
		return usr, dc.Scope, nil
	default:
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_grant", "无效的设备码状态")
		return nil, "", errGrantHandled
	}
}

// errGrantHandled is a sentinel error indicating the grant handler already wrote an HTTP response.
var errGrantHandled = &grantError{}

type grantError struct{}

func (e *grantError) Error() string { return "grant handled" }
