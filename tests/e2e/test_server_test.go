package e2e

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/eugenioenko/autentico/pkg/account"
	"github.com/eugenioenko/autentico/pkg/admin"
	"github.com/eugenioenko/autentico/pkg/deletion"
	"github.com/eugenioenko/autentico/pkg/appsettings"
	"github.com/eugenioenko/autentico/pkg/authorize"
	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/group"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/introspect"
	"github.com/eugenioenko/autentico/pkg/key"
	"github.com/eugenioenko/autentico/pkg/login"
	"github.com/eugenioenko/autentico/pkg/middleware"
	"github.com/eugenioenko/autentico/pkg/session"
	"github.com/eugenioenko/autentico/pkg/signup"
	"github.com/eugenioenko/autentico/pkg/token"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/userinfo"
	"github.com/eugenioenko/autentico/pkg/wellknown"
	"github.com/gorilla/csrf"
	"golang.org/x/crypto/bcrypt"
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

	// Seed the shared "test-client" used across E2E tests
	_, err = db.GetDB().Exec(`
		INSERT INTO clients (id, client_id, client_name, client_type, redirect_uris, post_logout_redirect_uris, grant_types, response_types, scopes, is_active)
		VALUES ('test-client-id', 'test-client', 'E2E Test Client', 'public', '["http://localhost:3000/callback"]', '[]', '["authorization_code","password","refresh_token"]', '["code","token"]', 'openid profile email offline_access groups', TRUE)
	`)
	if err != nil {
		t.Fatalf("Failed to seed test-client: %v", err)
	}

	// Seed a shared confidential client for introspect/revoke E2E tests
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte("e2e-secret"), bcrypt.MinCost)
	_, err = db.GetDB().Exec(`
		INSERT INTO clients (id, client_id, client_name, client_secret, client_type, redirect_uris, post_logout_redirect_uris, grant_types, response_types, scopes, is_active)
		VALUES ('e2e-conf-id', 'e2e-confidential', 'E2E Confidential Client', ?, 'confidential', '["http://localhost:3000/callback"]', '[]', '["authorization_code","password","refresh_token"]', '["code","token"]', 'openid profile email offline_access groups', TRUE)
	`, string(hashedSecret))
	if err != nil {
		t.Fatalf("Failed to seed e2e-confidential client: %v", err)
	}

	// Ensure RSA keys are loaded (generates if no file found)
	key.GetPrivateKey()

	// Create an unstarted server to discover the assigned port
	server := httptest.NewUnstartedServer(nil)
	host := server.Listener.Addr().String()
	baseURL := "http://" + host

	// Override config to match test server URL
	oauth := config.GetBootstrap().AppOAuthPath
	config.Bootstrap.AppURL = baseURL
	config.Bootstrap.AppHost = host
	config.Bootstrap.AppAuthIssuer = baseURL + oauth
	config.Bootstrap.AuthCSRFSecureCookie = false
	config.Bootstrap.AuthAccessTokenSecret = "test-access-token-secret-for-e2e!!"
	config.Bootstrap.AuthRefreshTokenSecret = "test-refresh-token-secret-for-e2e!"
	config.Bootstrap.AuthCSRFProtectionSecretKey = "test-csrf-protection-secret-e2e!!"

	// Create CSRF middleware for the test server.
	// gorilla/csrf v1.7.3 assumes HTTPS by default and rejects HTTP referers.
	// We wrap handlers with plaintextCSRF which marks requests as plaintext
	// (via csrf.PlaintextHTTPRequest) so the strict referer check is skipped.
	csrfProtect := csrf.Protect(
		[]byte(config.GetBootstrap().AuthCSRFProtectionSecretKey),
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
	mux.HandleFunc("/.well-known/openid-configuration", wellknown.HandleWellKnownConfig)
	mux.HandleFunc(oauth+"/.well-known/openid-configuration", wellknown.HandleWellKnownConfig)
	mux.HandleFunc(oauth+"/.well-known/jwks.json", wellknown.HandleJWKS)
	mux.HandleFunc(oauth+"/token", token.HandleToken)
	mux.HandleFunc(oauth+"/protocol/openid-connect/token", token.HandleToken)
	mux.HandleFunc(oauth+"/revoke", token.HandleRevoke)
	mux.HandleFunc(oauth+"/userinfo", userinfo.HandleUserInfo)
	mux.HandleFunc(oauth+"/protocol/openid-connect/userinfo", userinfo.HandleUserInfo)
	mux.HandleFunc("POST "+oauth+"/logout", session.HandleLogout)
	mux.HandleFunc("GET "+oauth+"/logout", session.HandleRpInitiatedLogout)
	mux.HandleFunc(oauth+"/introspect", introspect.HandleIntrospect)

	// CSRF-protected routes (using plaintext wrapper for HTTP test server)
	mux.Handle(oauth+"/authorize", plaintextCSRF(http.HandlerFunc(authorize.HandleAuthorize)))
	mux.Handle(oauth+"/login", plaintextCSRF(http.HandlerFunc(login.HandleLoginUser)))
	mux.Handle(oauth+"/signup", plaintextCSRF(http.HandlerFunc(signup.HandleSignup)))

	// OAuth2 client registration (admin-protected)
	mux.Handle("GET "+oauth+"/register", middleware.AdminAuthMiddleware(http.HandlerFunc(client.HandleListClients)))
	mux.Handle("POST "+oauth+"/register", middleware.AdminAuthMiddleware(http.HandlerFunc(client.HandleRegister)))
	mux.Handle("GET "+oauth+"/register/{client_id}", middleware.AdminAuthMiddleware(http.HandlerFunc(client.HandleGetClient)))
	mux.Handle("PUT "+oauth+"/register/{client_id}", middleware.AdminAuthMiddleware(http.HandlerFunc(client.HandleUpdateClient)))
	mux.Handle("DELETE "+oauth+"/register/{client_id}", middleware.AdminAuthMiddleware(http.HandlerFunc(client.HandleDeleteClient)))

	// Account API routes
	mux.HandleFunc("GET /account/api/profile", account.HandleGetProfile)
	mux.HandleFunc("PUT /account/api/profile", account.HandleUpdateProfile)
	mux.HandleFunc("POST /account/api/password", account.HandleUpdatePassword)
	mux.HandleFunc("GET /account/api/sessions", account.HandleListSessions)
	mux.HandleFunc("DELETE /account/api/sessions/{id}", account.HandleRevokeSession)
	mux.HandleFunc("GET /account/api/mfa", account.HandleGetMfaStatus)
	mux.HandleFunc("POST /account/api/mfa/totp/setup", account.HandleSetupTotp)
	mux.HandleFunc("POST /account/api/mfa/totp/verify", account.HandleVerifyTotp)
	mux.HandleFunc("DELETE /account/api/mfa/totp", account.HandleDeleteMfa)
	mux.HandleFunc("GET /account/api/settings", account.HandleGetSettings)
	mux.HandleFunc("GET /account/api/deletion-request", deletion.HandleGetDeletionRequest)
	mux.HandleFunc("POST /account/api/deletion-request", deletion.HandleRequestDeletion)
	mux.HandleFunc("DELETE /account/api/deletion-request", deletion.HandleCancelDeletionRequest)

	// Admin API routes
	mux.Handle("GET /admin/api/users", middleware.AdminAuthMiddleware(http.HandlerFunc(user.HandleListUsers)))
	mux.Handle("POST /admin/api/users", middleware.AdminAuthMiddleware(http.HandlerFunc(user.HandleCreateUser)))
	mux.Handle("GET /admin/api/users/{id}", middleware.AdminAuthMiddleware(http.HandlerFunc(user.HandleGetUser)))
	mux.Handle("PUT /admin/api/users/{id}", middleware.AdminAuthMiddleware(http.HandlerFunc(user.HandleUpdateUser)))
	mux.Handle("DELETE /admin/api/users/{id}", middleware.AdminAuthMiddleware(http.HandlerFunc(user.HandleDeleteUser)))
	mux.Handle("POST /admin/api/users/{id}/deactivate", middleware.AdminAuthMiddleware(http.HandlerFunc(user.HandleDeactivateUser)))
	mux.Handle("POST /admin/api/users/{id}/reactivate", middleware.AdminAuthMiddleware(http.HandlerFunc(user.HandleReactivateUser)))
	mux.Handle("POST /admin/api/users/{id}/unlock", middleware.AdminAuthMiddleware(http.HandlerFunc(user.HandleUnlockUser)))
	mux.Handle("GET /admin/api/clients", middleware.AdminAuthMiddleware(http.HandlerFunc(client.HandleListClients)))
	mux.Handle("POST /admin/api/clients", middleware.AdminAuthMiddleware(http.HandlerFunc(client.HandleRegister)))
	mux.Handle("GET /admin/api/clients/{client_id}", middleware.AdminAuthMiddleware(http.HandlerFunc(client.HandleGetClient)))
	mux.Handle("PUT /admin/api/clients/{client_id}", middleware.AdminAuthMiddleware(http.HandlerFunc(client.HandleUpdateClient)))
	mux.Handle("DELETE /admin/api/clients/{client_id}", middleware.AdminAuthMiddleware(http.HandlerFunc(client.HandleDeleteClient)))
	mux.Handle("GET /admin/api/sessions", middleware.AdminAuthMiddleware(http.HandlerFunc(session.HandleListSessions)))
	mux.Handle("DELETE /admin/api/sessions/{id}", middleware.AdminAuthMiddleware(http.HandlerFunc(session.HandleDeactivateSession)))
	mux.Handle("GET /admin/api/stats", middleware.AdminAuthMiddleware(http.HandlerFunc(admin.HandleStats)))
	mux.Handle("GET /admin/api/settings", middleware.AdminAuthMiddleware(http.HandlerFunc(appsettings.HandleGetSettings)))
	mux.Handle("PUT /admin/api/settings", middleware.AdminAuthMiddleware(http.HandlerFunc(appsettings.HandlePutSettings)))
	mux.Handle("GET /admin/api/deletion-requests", middleware.AdminAuthMiddleware(http.HandlerFunc(deletion.HandleListDeletionRequests)))
	mux.Handle("POST /admin/api/deletion-requests/{id}/approve", middleware.AdminAuthMiddleware(http.HandlerFunc(deletion.HandleApproveDeletionRequest)))
	mux.Handle("DELETE /admin/api/deletion-requests/{id}", middleware.AdminAuthMiddleware(http.HandlerFunc(deletion.HandleAdminCancelDeletionRequest)))
	mux.Handle("GET /admin/api/groups", middleware.AdminAuthMiddleware(http.HandlerFunc(group.HandleListGroups)))
	mux.Handle("POST /admin/api/groups", middleware.AdminAuthMiddleware(http.HandlerFunc(group.HandleCreateGroup)))
	mux.Handle("GET /admin/api/groups/{id}", middleware.AdminAuthMiddleware(http.HandlerFunc(group.HandleGetGroup)))
	mux.Handle("PUT /admin/api/groups/{id}", middleware.AdminAuthMiddleware(http.HandlerFunc(group.HandleUpdateGroup)))
	mux.Handle("DELETE /admin/api/groups/{id}", middleware.AdminAuthMiddleware(http.HandlerFunc(group.HandleDeleteGroup)))
	mux.Handle("GET /admin/api/groups/{id}/members", middleware.AdminAuthMiddleware(http.HandlerFunc(group.HandleListMembers)))
	mux.Handle("POST /admin/api/groups/{id}/members", middleware.AdminAuthMiddleware(http.HandlerFunc(group.HandleAddMember)))
	mux.Handle("DELETE /admin/api/groups/{id}/members/{user_id}", middleware.AdminAuthMiddleware(http.HandlerFunc(group.HandleRemoveMember)))
	mux.Handle("GET /admin/api/users/{id}/groups", middleware.AdminAuthMiddleware(http.HandlerFunc(group.HandleGetUserGroups)))

	// Apply CORS + logging middleware and start server
	server.Config.Handler = middleware.CORSMiddleware(middleware.LoggingMiddleware(mux))
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
