package e2e

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/eugenioenko/autentico/pkg/authorize"
	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/introspect"
	"github.com/eugenioenko/autentico/pkg/key"
	"github.com/eugenioenko/autentico/pkg/login"
	"github.com/eugenioenko/autentico/pkg/middleware"
	"github.com/eugenioenko/autentico/pkg/session"
	"github.com/eugenioenko/autentico/pkg/token"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/userinfo"
	"github.com/eugenioenko/autentico/pkg/wellknown"
	"github.com/gorilla/csrf"
)

// TestServer wraps httptest.Server with helpers for E2E testing.
type TestServer struct {
	Server  *httptest.Server
	Client  *http.Client
	BaseURL string
}

// startTestServer creates a fully-configured test server replicating main.go routing.
// It initializes an in-memory database, loads RSA keys, registers all routes with
// appropriate middleware, and configures the config to match the test server URL.
func startTestServer(t *testing.T) *TestServer {
	t.Helper()

	// Initialize in-memory database
	_, err := db.InitTestDB()
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}

	// Ensure RSA keys are loaded (generates if no file found)
	key.GetPrivateKey()

	// Create an unstarted server to discover the assigned port
	server := httptest.NewUnstartedServer(nil)
	host := server.Listener.Addr().String()
	baseURL := "http://" + host

	// Override config to match test server URL
	oauth := config.Get().AppOAuthPath
	config.Values.AppURL = baseURL
	config.Values.AppHost = host
	config.Values.AppAuthIssuer = baseURL + oauth
	config.Values.AuthCSRFSecureCookie = false

	// Create CSRF middleware for the test server.
	// gorilla/csrf v1.7.3 assumes HTTPS by default and rejects HTTP referers.
	// We wrap handlers with plaintextCSRF which marks requests as plaintext
	// (via csrf.PlaintextHTTPRequest) so the strict referer check is skipped.
	csrfProtect := csrf.Protect(
		[]byte(config.Get().AuthCSRFProtectionSecretKey),
		csrf.Secure(false),
		csrf.Path("/"),
	)
	plaintextCSRF := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r = csrf.PlaintextHTTPRequest(r)
			csrfProtect(h).ServeHTTP(w, r)
		})
	}

	// Build mux replicating main.go routes
	mux := http.NewServeMux()

	// Public routes
	mux.HandleFunc("/user", user.HandleCreateUser)
	mux.HandleFunc("/.well-known/openid-configuration", wellknown.HandleWellKnownConfig)
	mux.HandleFunc(oauth+"/.well-known/openid-configuration", wellknown.HandleWellKnownConfig)
	mux.HandleFunc("/.well-known/jwks.json", wellknown.HandleJWKS)
	mux.HandleFunc(oauth+"/token", token.HandleToken)
	mux.HandleFunc(oauth+"/protocol/openid-connect/token", token.HandleToken)
	mux.HandleFunc(oauth+"/revoke", token.HandleRevoke)
	mux.HandleFunc(oauth+"/userinfo", userinfo.HandleUserInfo)
	mux.HandleFunc(oauth+"/protocol/openid-connect/userinfo", userinfo.HandleUserInfo)
	mux.HandleFunc(oauth+"/logout", session.HandleLogout)
	mux.HandleFunc(oauth+"/introspect", introspect.HandleIntrospect)

	// CSRF-protected routes (using plaintext wrapper for HTTP test server)
	mux.Handle(oauth+"/authorize", plaintextCSRF(http.HandlerFunc(authorize.HandleAuthorize)))
	mux.Handle(oauth+"/login", plaintextCSRF(http.HandlerFunc(login.HandleLoginUser)))

	// Admin-protected routes
	mux.Handle(oauth+"/register", middleware.AdminAuthMiddleware(http.HandlerFunc(client.HandleClientEndpoint)))
	mux.Handle(oauth+"/register/", middleware.AdminAuthMiddleware(http.HandlerFunc(client.HandleClientEndpoint)))

	// Admin API routes
	mux.Handle("/admin/api/users", middleware.AdminAuthMiddleware(http.HandlerFunc(user.HandleUserAdminEndpoint)))
	mux.Handle("/admin/api/clients", middleware.AdminAuthMiddleware(http.HandlerFunc(client.HandleClientEndpoint)))
	mux.Handle("/admin/api/clients/", middleware.AdminAuthMiddleware(http.HandlerFunc(client.HandleClientEndpoint)))
	mux.Handle("/admin/api/sessions", middleware.AdminAuthMiddleware(http.HandlerFunc(session.HandleSessionAdminEndpoint)))

	// Apply logging middleware and start server
	server.Config.Handler = middleware.LoggingMiddleware(mux)
	server.Start()

	// Create HTTP client with cookie jar and no-redirect policy
	jar, _ := cookiejar.New(nil)
	httpClient := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	ts := &TestServer{
		Server:  server,
		Client:  httpClient,
		BaseURL: server.URL,
	}

	t.Cleanup(func() {
		server.Close()
		db.CloseDB()
	})

	return ts
}

// newClientWithJar returns a new HTTP client with a fresh cookie jar that
// does NOT follow redirects.
func newClientWithJar() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// getCSRFToken extracts the CSRF token value from the rendered login HTML body.
func getCSRFToken(body string) string {
	re := regexp.MustCompile(`<input type="hidden" name="gorilla\.csrf\.Token" value="([^"]+)"`)
	matches := re.FindStringSubmatch(body)
	if len(matches) < 2 {
		return ""
	}
	return matches[1]
}
