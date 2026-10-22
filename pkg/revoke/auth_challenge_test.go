package revoke

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestRevocationAuthenticationChallengesMatchTheScheme(t *testing.T) {
	for _, kind := range []string{"missing", "wrong Basic", "malformed Basic", "invalid Bearer"} {
		t.Run(kind, func(t *testing.T) {
			testutils.WithTestDB(t)
			testutils.InsertTestConfidentialClient(t, "challenge-client", "challenge-secret")
			r := httptest.NewRequest(http.MethodPost, "/oauth2/revoke", strings.NewReader("token=not-a-token"))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			scheme := "Basic"
			switch kind {
			case "wrong Basic":
				r.SetBasicAuth("challenge-client", "wrong")
			case "malformed Basic":
				r.Header.Set("Authorization", "Basic malformed")
			case "invalid Bearer":
				r.Header.Set("Authorization", "Bearer invalid")
				scheme = "Bearer"
			}
			rr := httptest.NewRecorder()
			HandleRevoke(rr, r)
			require.Equal(t, http.StatusUnauthorized, rr.Code, rr.Body.String())
			require.True(t, strings.HasPrefix(rr.Header().Get("WWW-Authenticate"), scheme+" "))
			if scheme == "Bearer" {
				require.Contains(t, rr.Header().Get("WWW-Authenticate"), `error="invalid_token"`)
			}
		})
	}
}
