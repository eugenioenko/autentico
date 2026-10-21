package security

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/middleware"
	"github.com/eugenioenko/autentico/pkg/ratelimit"
	"github.com/eugenioenko/autentico/pkg/utils"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestRateLimit_ForwardedHeadersCannotRotateClientIdentity(t *testing.T) {
	for _, trusted := range []bool{false, true} {
		t.Run(fmt.Sprint("trusted proxy=", trusted), func(t *testing.T) {
			testutils.WithConfigOverride(t, func() {
				config.Bootstrap.TrustedProxies = nil
				if trusted {
					config.Bootstrap.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
				}
			})
			store := ratelimit.NewStore(0.001, 1, 0, 100)
			server := httptest.NewServer(middleware.RateLimitMiddleware(store)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, utils.GetClientIP(r))
			})))
			defer server.Close()
			for i := 0; i < 30; i++ {
				r, err := http.NewRequest("POST", server.URL+"/oauth2/token", nil)
				require.NoError(t, err)
				forwarded := fmt.Sprintf("203.0.113.%d", i+1)
				if trusted {
					forwarded += ", 198.51.100.10"
				}
				r.Header.Set("X-Forwarded-For", forwarded)
				r.Header.Set("X-Real-IP", fmt.Sprintf("192.0.2.%d", i+1))
				resp, err := server.Client().Do(r)
				require.NoError(t, err)
				body, err := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				require.NoError(t, err)
				if i == 0 {
					require.Equal(t, 200, resp.StatusCode)
					want := "127.0.0.1"
					if trusted {
						want = "198.51.100.10"
					}
					require.Equal(t, want, string(body))
				} else {
					require.Equal(t, 429, resp.StatusCode, "rotating header %d must share one budget", i)
				}
			}
			if trusted {
				r, err := http.NewRequest("POST", server.URL+"/oauth2/token", nil)
				require.NoError(t, err)
				r.Header.Set("X-Forwarded-For", "203.0.113.99, 198.51.100.11")
				resp, err := server.Client().Do(r)
				require.NoError(t, err)
				_ = resp.Body.Close()
				require.Equal(t, 200, resp.StatusCode, "a different genuine client has an independent budget")
			}
		})
	}
}
