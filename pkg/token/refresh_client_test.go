package token

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestRefreshGrantRequiresClientBeforeTokenLookup(t *testing.T) {
	testutils.WithTestDB(t)
	for _, body := range []string{
		"grant_type=refresh_token&refresh_token=untrusted-token",
		"grant_type=refresh_token&refresh_token=untrusted-token&client_secret=secret-without-client",
	} {
		r := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		HandleToken(w, r)
		require.Equal(t, http.StatusUnauthorized, w.Code)
		require.Contains(t, w.Body.String(), "invalid_client")
	}
}
