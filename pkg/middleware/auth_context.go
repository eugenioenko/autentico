package middleware

import (
	"context"
	"net/http"

	"github.com/eugenioenko/autentico/pkg/jwtutil"
	"github.com/eugenioenko/autentico/pkg/session"
	"github.com/eugenioenko/autentico/pkg/user"
)

type authContextKey string

const authInfoKey authContextKey = "auth_info"

type AuthInfo struct {
	User    *user.User
	Token   string
	Claims  *jwtutil.AccessTokenClaims
	Session *session.Session
}

func setAuthInfo(r *http.Request, info *AuthInfo) *http.Request {
	ctx := context.WithValue(r.Context(), authInfoKey, info)
	return r.WithContext(ctx)
}

func AuthInfoFromContext(ctx context.Context) *AuthInfo {
	info, _ := ctx.Value(authInfoKey).(*AuthInfo)
	return info
}

func UserFromContext(ctx context.Context) *user.User {
	if info := AuthInfoFromContext(ctx); info != nil {
		return info.User
	}
	return nil
}

func WithAuthInfo(r *http.Request, info *AuthInfo) *http.Request {
	return setAuthInfo(r, info)
}
