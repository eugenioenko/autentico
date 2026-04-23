package security

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/eugenioenko/autentico/pkg/account"
	"github.com/eugenioenko/autentico/pkg/admin"
	"github.com/eugenioenko/autentico/pkg/appsettings"
	"github.com/eugenioenko/autentico/pkg/authorize"
	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/deletion"
	"github.com/eugenioenko/autentico/pkg/federation"
	"github.com/eugenioenko/autentico/pkg/group"
	"github.com/eugenioenko/autentico/pkg/introspect"
	"github.com/eugenioenko/autentico/pkg/key"
	"github.com/eugenioenko/autentico/pkg/login"
	"github.com/eugenioenko/autentico/pkg/middleware"
	"github.com/eugenioenko/autentico/pkg/revoke"
	"github.com/eugenioenko/autentico/pkg/session"
	"github.com/eugenioenko/autentico/pkg/signup"
	"github.com/eugenioenko/autentico/pkg/token"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/userinfo"
	"github.com/eugenioenko/autentico/pkg/wellknown"
	"github.com/gorilla/csrf"
	"golang.org/x/crypto/bcrypt"
)

type TestServer struct {
	Server  *httptest.Server
	Client  *http.Client
	BaseURL string
}

func startTestServer(t *testing.T) *TestServer {
	t.Helper()

	_, err := db.InitTestDB()
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}

	// Public test client
	_, err = db.GetDB().Exec(`
		INSERT INTO clients (id, client_id, client_name, client_type, redirect_uris, post_logout_redirect_uris, grant_types, response_types, scopes, is_active)
		VALUES ('test-client-id', 'test-client', 'Security Test Client', 'public', '["http://localhost:3000/callback"]', '["http://localhost:3000/logout"]', '["authorization_code","password","refresh_token"]', '["code"]', 'openid profile email offline_access', TRUE)
	`)
	if err != nil {
		t.Fatalf("Failed to seed test-client: %v", err)
	}

	// Admin client
	_, err = db.GetDB().Exec(`
		INSERT INTO clients (id, client_id, client_name, client_type, redirect_uris, post_logout_redirect_uris, grant_types, response_types, scopes, is_active)
		VALUES ('autentico-admin-id', 'autentico-admin', 'Autentico Admin', 'public', '["http://localhost:3000/admin/callback"]', '[]', '["authorization_code","password","refresh_token"]', '["code"]', 'openid profile email offline_access', TRUE)
	`)
	if err != nil {
		t.Fatalf("Failed to seed autentico-admin client: %v", err)
	}

	// Confidential test client
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte("sec-secret"), bcrypt.MinCost)
	_, err = db.GetDB().Exec(`
		INSERT INTO clients (id, client_id, client_name, client_secret, client_type, redirect_uris, post_logout_redirect_uris, grant_types, response_types, scopes, is_active)
		VALUES ('sec-conf-id', 'sec-confidential', 'Security Confidential Client', ?, 'confidential', '["http://localhost:3000/callback"]', '[]', '["authorization_code","password","refresh_token"]', '["code"]', 'openid profile email offline_access', TRUE)
	`, string(hashedSecret))
	if err != nil {
		t.Fatalf("Failed to seed sec-confidential client: %v", err)
	}

	// Second client for cross-client tests
	_, err = db.GetDB().Exec(`
		INSERT INTO clients (id, client_id, client_name, client_type, redirect_uris, post_logout_redirect_uris, grant_types, response_types, scopes, is_active)
		VALUES ('other-client-id', 'other-client', 'Other Client', 'public', '["http://other.example.com/callback"]', '[]', '["authorization_code","password","refresh_token"]', '["code"]', 'openid profile email', TRUE)
	`)
	if err != nil {
		t.Fatalf("Failed to seed other-client: %v", err)
	}

	key.GetPrivateKey()

	server := httptest.NewUnstartedServer(nil)
	host := server.Listener.Addr().String()
	baseURL := "http://" + host

	oauth := config.GetBootstrap().AppOAuthPath
	config.Bootstrap.AppURL = baseURL
	config.Bootstrap.AppHost = host
	config.Bootstrap.AppAuthIssuer = baseURL + oauth
	config.Bootstrap.AuthCSRFSecureCookie = false
	config.Bootstrap.AuthAccessTokenSecret = "test-access-token-secret-security!!"
	config.Bootstrap.AuthRefreshTokenSecret = "test-refresh-token-secret-security!"
	config.Bootstrap.AuthCSRFProtectionSecretKey = "test-csrf-secret-key-security-test!"

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

	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", wellknown.HandleWellKnownConfig)
	mux.HandleFunc(oauth+"/.well-known/openid-configuration", wellknown.HandleWellKnownConfig)
	mux.HandleFunc(oauth+"/.well-known/jwks.json", wellknown.HandleJWKS)
	mux.HandleFunc(oauth+"/token", token.HandleToken)
	mux.HandleFunc(oauth+"/revoke", revoke.HandleRevoke)
	mux.HandleFunc(oauth+"/userinfo", userinfo.HandleUserInfo)
	mux.HandleFunc("POST "+oauth+"/logout", session.HandleLogout)
	mux.HandleFunc("GET "+oauth+"/logout", session.HandleRpInitiatedLogout)
	mux.HandleFunc(oauth+"/introspect", introspect.HandleIntrospect)

	mux.Handle(oauth+"/authorize", plaintextCSRF(http.HandlerFunc(authorize.HandleAuthorize)))
	mux.Handle(oauth+"/login", plaintextCSRF(http.HandlerFunc(login.HandleLoginUser)))
	mux.Handle(oauth+"/signup", plaintextCSRF(http.HandlerFunc(signup.HandleSignup)))

	mux.Handle("POST "+oauth+"/register", middleware.AdminAuthMiddleware(http.HandlerFunc(client.HandleRegister)))
	mux.Handle("GET "+oauth+"/register/{client_id}", middleware.AdminAuthMiddleware(http.HandlerFunc(client.HandleGetClient)))

	mux.HandleFunc("GET /account/api/profile", account.HandleGetProfile)
	mux.HandleFunc("PUT /account/api/profile", account.HandleUpdateProfile)

	mux.Handle("GET /admin/api/users", middleware.AdminAuthMiddleware(http.HandlerFunc(user.HandleListUsers)))
	mux.Handle("POST /admin/api/users", middleware.AdminAuthMiddleware(http.HandlerFunc(user.HandleCreateUser)))
	mux.Handle("GET /admin/api/settings", middleware.AdminAuthMiddleware(http.HandlerFunc(appsettings.HandleGetSettings)))
	mux.Handle("PUT /admin/api/settings", middleware.AdminAuthMiddleware(http.HandlerFunc(appsettings.HandlePutSettings)))
	mux.Handle("GET /admin/api/stats", middleware.AdminAuthMiddleware(http.HandlerFunc(admin.HandleStats)))
	mux.Handle("GET /admin/api/groups", middleware.AdminAuthMiddleware(http.HandlerFunc(group.HandleListGroups)))
	mux.Handle("GET /admin/api/deletion-requests", middleware.AdminAuthMiddleware(http.HandlerFunc(deletion.HandleListDeletionRequests)))

	mux.Handle("POST /admin/api/federation/providers", middleware.AdminAuthMiddleware(http.HandlerFunc(federation.HandleCreateProvider)))

	server.Config.Handler = middleware.CORSMiddleware(middleware.LoggingMiddleware(mux))
	server.Start()

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

func newClientWithJar() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func getCSRFToken(body string) string {
	re := regexp.MustCompile(`<input type="hidden" name="gorilla\.csrf\.Token" value="([^"]+)"`)
	matches := re.FindStringSubmatch(body)
	if len(matches) < 2 {
		return ""
	}
	return matches[1]
}

func getAuthorizeSig(body string) string {
	re := regexp.MustCompile(`<input type="hidden" name="authorize_sig" value="([^"]*)"`)
	matches := re.FindStringSubmatch(body)
	if len(matches) < 2 {
		return ""
	}
	return matches[1]
}
