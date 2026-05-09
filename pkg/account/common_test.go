package account

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/jwtutil"
	"github.com/eugenioenko/autentico/pkg/key"
	"github.com/eugenioenko/autentico/pkg/middleware"
	"github.com/eugenioenko/autentico/pkg/session"
	"github.com/eugenioenko/autentico/pkg/user"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func setupTestUserAndSession(t *testing.T) (string, *user.User, *middleware.AuthInfo) {
	userID := uuid.New().String()
	testutils.InsertTestUser(t, userID)

	usr, err := user.UserByID(userID)
	assert.NoError(t, err)

	sessionID := uuid.New().String()

	claims := &jwtutil.AccessTokenClaims{
		UserID:    usr.ID,
		SessionID: sessionID,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(key.GetPrivateKey())
	assert.NoError(t, err)

	sess := session.Session{
		ID:           sessionID,
		UserID:       usr.ID,
		AccessToken:  tokenString,
		RefreshToken: "test-refresh-token",
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	err = session.CreateSession(sess)
	assert.NoError(t, err)

	now := time.Now().UTC()
	_, err = db.GetDB().Exec(`
		INSERT INTO tokens (id, user_id, access_token, refresh_token, access_token_type,
			refresh_token_expires_at, access_token_expires_at, issued_at, scope, grant_type)
		VALUES (?, ?, ?, ?, 'Bearer', ?, ?, ?, 'openid', 'password')
	`, "tok-"+sessionID[:8], usr.ID, tokenString, "refresh-"+sessionID[:8], now.Add(time.Hour), now.Add(time.Hour), now)
	assert.NoError(t, err)

	info := &middleware.AuthInfo{
		User:    usr,
		Token:   tokenString,
		Claims:  claims,
		Session: &sess,
	}

	return tokenString, usr, info
}

func mockAuthRequest(t *testing.T, body, method, url string, handler http.HandlerFunc, info *middleware.AuthInfo) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, url, bytes.NewBuffer([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	if info != nil {
		if usr, err := user.UserByID(info.User.ID); err == nil {
			info = &middleware.AuthInfo{
				User:    usr,
				Token:   info.Token,
				Claims:  info.Claims,
				Session: info.Session,
			}
		}
		req = middleware.WithAuthInfo(req, info)
	}
	rr := httptest.NewRecorder()
	handler(rr, req)
	return rr
}
