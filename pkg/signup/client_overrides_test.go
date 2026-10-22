package signup

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestSignupClientOverrides(t *testing.T) {
	for _, tc := range []struct {
		name     string
		global   bool
		override any
		allowed  bool
	}{
		{"client denies", true, false, false}, {"client allows", false, true, true}, {"inherit allowed", true, nil, true}, {"inherit denied", false, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withSignupTestDB(t)
			testutils.WithConfigOverride(t, func() {
				config.Values.AuthAllowSelfSignup = tc.global
				config.Values.RequireEmailVerification = false
				config.Values.AuthMode = "password"
			})
			_, err := db.GetDB().Exec(`UPDATE clients SET allow_self_signup=? WHERE client_id='test-client'`, tc.override)
			require.NoError(t, err)
			form := url.Values{"username": {"override-user"}, "password": {"Password123!"}, "confirm_password": {"Password123!"}, "email": {"override@example.com"}, "redirect_uri": {"http://localhost/callback"}}
			signSignupParams(form)
			req := httptest.NewRequest(http.MethodPost, "/oauth2/signup", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()
			HandleSignup(rr, req)
			expected := http.StatusMethodNotAllowed
			if tc.allowed {
				expected = http.StatusFound
			}
			require.Equal(t, expected, rr.Code, rr.Body.String())
			var count int
			require.NoError(t, db.GetDB().QueryRow(`SELECT count(*) FROM users WHERE username='override-user'`).Scan(&count))
			if tc.allowed {
				require.Equal(t, 1, count)
			} else {
				require.Zero(t, count)
			}
		})
	}
}
