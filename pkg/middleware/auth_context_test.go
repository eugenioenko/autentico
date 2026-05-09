package middleware

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/eugenioenko/autentico/pkg/jwtutil"
	"github.com/eugenioenko/autentico/pkg/session"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/stretchr/testify/assert"
)

func TestAuthInfoFromContext_Missing(t *testing.T) {
	ctx := context.Background()
	assert.Nil(t, AuthInfoFromContext(ctx))
}

func TestUserFromContext_Missing(t *testing.T) {
	ctx := context.Background()
	assert.Nil(t, UserFromContext(ctx))
}

func TestAuthInfoFromContext_Present(t *testing.T) {
	info := &AuthInfo{
		User:    &user.User{ID: "u1", Username: "alice"},
		Token:   "tok-123",
		Claims:  &jwtutil.AccessTokenClaims{UserID: "u1", SessionID: "s1"},
		Session: &session.Session{ID: "s1", UserID: "u1"},
	}

	req := httptest.NewRequest("GET", "/", nil)
	req = setAuthInfo(req, info)

	got := AuthInfoFromContext(req.Context())
	assert.NotNil(t, got)
	assert.Equal(t, "u1", got.User.ID)
	assert.Equal(t, "tok-123", got.Token)
	assert.Equal(t, "s1", got.Claims.SessionID)
	assert.Equal(t, "s1", got.Session.ID)
}

func TestUserFromContext_Present(t *testing.T) {
	info := &AuthInfo{
		User: &user.User{ID: "u1", Username: "alice"},
	}

	req := httptest.NewRequest("GET", "/", nil)
	req = setAuthInfo(req, info)

	usr := UserFromContext(req.Context())
	assert.NotNil(t, usr)
	assert.Equal(t, "u1", usr.ID)
	assert.Equal(t, "alice", usr.Username)
}

func TestWithAuthInfo_SameAsSetAuthInfo(t *testing.T) {
	info := &AuthInfo{
		User:  &user.User{ID: "u1"},
		Token: "tok",
	}

	req := httptest.NewRequest("GET", "/", nil)
	req = WithAuthInfo(req, info)

	got := AuthInfoFromContext(req.Context())
	assert.Equal(t, info, got)
}

func TestSetAuthInfo_Overwrites(t *testing.T) {
	first := &AuthInfo{User: &user.User{ID: "u1"}}
	second := &AuthInfo{User: &user.User{ID: "u2"}}

	req := httptest.NewRequest("GET", "/", nil)
	req = setAuthInfo(req, first)
	req = setAuthInfo(req, second)

	got := AuthInfoFromContext(req.Context())
	assert.Equal(t, "u2", got.User.ID)
}

func TestUserFromContext_NilUser(t *testing.T) {
	info := &AuthInfo{User: nil, Token: "tok"}

	req := httptest.NewRequest("GET", "/", nil)
	req = setAuthInfo(req, info)

	assert.Nil(t, UserFromContext(req.Context()))
}
