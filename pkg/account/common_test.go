package account

import (
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/jwtutil"
	"github.com/eugenioenko/autentico/pkg/key"
	"github.com/eugenioenko/autentico/pkg/session"
	"github.com/eugenioenko/autentico/pkg/user"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func setupTestUserAndSession(t *testing.T) (string, *user.User) {
	userID := uuid.New().String()
	testutils.InsertTestUser(t, userID)
	
	usr, err := user.UserByID(userID)
	assert.NoError(t, err)

	sessionID := uuid.New().String()
	
	// Create a valid JWT token signed with the ephemeral test key
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

	// Persist the matching tokens row so bearer.ValidateBearer's
	// revocation check sees an active row (not sql.ErrNoRows).
	now := time.Now().UTC()
	_, err = db.GetDB().Exec(`
		INSERT INTO tokens (id, user_id, access_token, refresh_token, access_token_type,
			refresh_token_expires_at, access_token_expires_at, issued_at, scope, grant_type)
		VALUES (?, ?, ?, ?, 'Bearer', ?, ?, ?, 'openid', 'password')
	`, "tok-"+sessionID[:8], usr.ID, tokenString, "refresh-"+sessionID[:8], now.Add(time.Hour), now.Add(time.Hour), now)
	assert.NoError(t, err)

	return tokenString, usr
}
