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
	for _, tt := range []struct {
		body   string
		status int
		code   string
	}{
		{"grant_type=refresh_token&refresh_token=untrusted-token", http.StatusUnauthorized, "invalid_client"},
		// RFC 6749 §5.2: an incomplete body credential set is malformed;
		// neither failure may proceed to refresh-token decoding or lookup.
		{"grant_type=refresh_token&refresh_token=untrusted-token&client_secret=secret-without-client", http.StatusBadRequest, "invalid_request"},
	} {
		r := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(tt.body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		HandleToken(w, r)
		require.Equal(t, tt.status, w.Code)
		require.Contains(t, w.Body.String(), tt.code)
	}
}
