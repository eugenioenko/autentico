package token

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/user"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

// RFC 9700 §4.8.2: a verifier without an original challenge must be rejected.
func TestCodeWithoutChallengeRejectsVerifier(t *testing.T) {
	for _, verifier := range []string{"", strings.Repeat("a", 43), "short"} {
		t.Run("verifier="+verifier, func(t *testing.T) {
			testutils.WithTestDB(t)
			testutils.InsertTestConfidentialClient(t, "no-pkce", "secret")
			usr, err := user.CreateUser("pkce-downgrade", "password123", "")
			require.NoError(t, err)
			require.NoError(t, authcode.CreateAuthCode(authcode.AuthCode{Code: "no-challenge", UserID: usr.ID, ClientID: "no-pkce", RedirectURI: "http://localhost/callback", Scope: "openid", ExpiresAt: time.Now().Add(time.Minute)}))
			request := TokenRequest{GrantType: "authorization_code", Code: "no-challenge", ClientID: "no-pkce", RedirectURI: "http://localhost/callback", CodeVerifier: verifier}
			recorder := httptest.NewRecorder()
			_, _, err = UserByAuthorizationCode(recorder, request)
			if verifier == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				require.Equal(t, 400, recorder.Code)
				require.Contains(t, recorder.Body.String(), "invalid_grant")
				stored, err := authcode.AuthCodeByCodeIncludingUsed("no-challenge")
				require.NoError(t, err)
				require.False(t, stored.Used)
			}
		})
	}
}
