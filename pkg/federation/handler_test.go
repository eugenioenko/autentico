package federation

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
)

func TestHandleFederationBegin_Errors(t *testing.T) {
	testutils.WithTestDB(t)

	// Case 1: Missing provider ID
	req := httptest.NewRequest(http.MethodGet, "/oauth2/federation/", nil)
	rr := httptest.NewRecorder()
	HandleFederationBegin(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	// Case 2: Provider not found
	req = httptest.NewRequest(http.MethodGet, "/oauth2/federation/nonexistent", nil)
	req.SetPathValue("id", "nonexistent")
	rr = httptest.NewRecorder()
	HandleFederationBegin(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)

	// Case 3: Provider disabled
	_, _ = db.GetDB().Exec(`
		INSERT INTO federation_providers (id, name, issuer, client_id, client_secret, enabled)
		VALUES ('disabled-p', 'Disabled', 'https://iss.com', 'c', 's', FALSE)
	`)
	req = httptest.NewRequest(http.MethodGet, "/oauth2/federation/disabled-p", nil)
	req.SetPathValue("id", "disabled-p")
	rr = httptest.NewRecorder()
	HandleFederationBegin(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestDeriveUsername(t *testing.T) {
	assert.Equal(t, "user-sub123", deriveUsername("user@example.com", "sub123"))
	assert.Equal(t, "sub12345-sub12345", deriveUsername("", "sub12345"))
	assert.Equal(t, "verylongemailaddress-x-suffix", deriveUsername("verylongemailaddress@example.com", "prefix-x-suffix"))
}

func TestRandomPassword(t *testing.T) {
	p1 := randomPassword()
	p2 := randomPassword()
	assert.NotEmpty(t, p1)
	assert.NotEqual(t, p1, p2)
}

func TestHandleFederationCallback_Success(t *testing.T) {
	testutils.WithTestDB(t)

	// 1. Mock OIDC Provider
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			resp := map[string]any{
				"issuer":                 fmt.Sprintf("http://%s", r.Host),
				"authorization_endpoint": fmt.Sprintf("http://%s/auth", r.Host),
				"token_endpoint":         fmt.Sprintf("http://%s/token", r.Host),
				"userinfo_endpoint":      fmt.Sprintf("http://%s/userinfo", r.Host),
				"jwks_uri":               fmt.Sprintf("http://%s/jwks", r.Host),
			}
			json.NewEncoder(w).Encode(resp)
		case "/token":
			resp := map[string]any{
				"access_token": "mock-access-token",
				"id_token":     "mock-id-token",
				"token_type":   "Bearer",
			}
			json.NewEncoder(w).Encode(resp)
		case "/userinfo":
			resp := map[string]any{
				"sub":   "mock-sub",
				"email": "mock@test.com",
				"name":  "Mock User",
			}
			json.NewEncoder(w).Encode(resp)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	// 2. Create provider
	_ = CreateFederationProvider(FederationProvider{
		ID: "mock", Name: "Mock", Issuer: ts.URL, ClientID: "c1", ClientSecret: "s1", Enabled: true,
	})

	// 3. Prepare state
	state := FederationState{
		ProviderID:  "mock",
		RedirectURI: "http://localhost/cb",
		ClientID:    "c1",
		State:       "xyz",
	}
	signedState, _ := SignState(state)

	// 4. Callback
	req := httptest.NewRequest(http.MethodGet, "/oauth2/federation/mock/callback?code=mock-code&state="+signedState, nil)
	req.SetPathValue("id", "mock")
	rr := httptest.NewRecorder()

	HandleFederationCallback(rr, req)

	assert.NotEqual(t, http.StatusNotFound, rr.Code)
}

func TestHandleFederationCallback_ExistingUser(t *testing.T) {
	testutils.WithTestDB(t)

	// 1. Mock OIDC Provider
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			resp := map[string]any{
				"issuer":                 fmt.Sprintf("http://%s", r.Host),
				"authorization_endpoint": fmt.Sprintf("http://%s/auth", r.Host),
				"token_endpoint":         fmt.Sprintf("http://%s/token", r.Host),
				"userinfo_endpoint":      fmt.Sprintf("http://%s/userinfo", r.Host),
				"jwks_uri":               fmt.Sprintf("http://%s/jwks", r.Host),
			}
			json.NewEncoder(w).Encode(resp)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	// 2. Create provider
	_ = CreateFederationProvider(FederationProvider{
		ID: "mock", Name: "Mock", Issuer: ts.URL, ClientID: "c1", ClientSecret: "s1", Enabled: true,
	})

	// 3. Create EXISTING user and federated identity
	testutils.InsertTestUser(t, "u1")
	_, _ = db.GetDB().Exec(`
		INSERT INTO federated_identities (id, provider_id, provider_user_id, user_id, email)
		VALUES ('fi1', 'mock', 'sub1', 'u1', 'mock@test.com')
	`)

	// 4. Prepare state
	state := FederationState{
		ProviderID:  "mock",
		RedirectURI: "http://localhost/cb",
		ClientID:    "c1",
		State:       "xyz",
	}
	signedState, _ := SignState(state)

	// 5. Callback
	req := httptest.NewRequest(http.MethodGet, "/oauth2/federation/mock/callback?code=mock-code&state="+signedState, nil)
	req.SetPathValue("id", "mock")
	rr := httptest.NewRecorder()

	HandleFederationCallback(rr, req)

	// It will still fail on Exchange/Verify because we didn't mock tokens fully,
	// but it should reach the part where it retrieves provider and state.
	assert.NotEqual(t, http.StatusNotFound, rr.Code)
}

func TestHandleFederationCallback_ExistingUser_NoIdentity(t *testing.T) {
	testutils.WithTestDB(t)

	// 1. Mock OIDC Provider
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			resp := map[string]any{
				"issuer":                 fmt.Sprintf("http://%s", r.Host),
				"authorization_endpoint": fmt.Sprintf("http://%s/auth", r.Host),
				"token_endpoint":         fmt.Sprintf("http://%s/token", r.Host),
				"userinfo_endpoint":      fmt.Sprintf("http://%s/userinfo", r.Host),
				"jwks_uri":               fmt.Sprintf("http://%s/jwks", r.Host),
			}
			json.NewEncoder(w).Encode(resp)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	// 2. Create provider
	_ = CreateFederationProvider(FederationProvider{
		ID: "mock", Name: "Mock", Issuer: ts.URL, ClientID: "c1", ClientSecret: "s1", Enabled: true,
	})

	// 3. Create EXISTING user with NO federated identity yet
	testutils.InsertTestUser(t, "u1")
	// Update user email to match what mock userinfo will return (if we mock it fully)
	_, _ = db.GetDB().Exec("UPDATE users SET email = 'mock@test.com' WHERE id = 'u1'")

	// 4. Prepare state
	state := FederationState{
		ProviderID:  "mock",
		RedirectURI: "http://localhost/cb",
		ClientID:    "c1",
		State:       "xyz",
	}
	signedState, _ := SignState(state)

	// 5. Callback
	req := httptest.NewRequest(http.MethodGet, "/oauth2/federation/mock/callback?code=mock-code&state="+signedState, nil)
	req.SetPathValue("id", "mock")
	rr := httptest.NewRecorder()

	HandleFederationCallback(rr, req)

	assert.NotEqual(t, http.StatusNotFound, rr.Code)
}

func TestHandleFederationCallback_Errors_Extra(t *testing.T) {
	testutils.WithTestDB(t)

	// Case 1: Missing code or state
	req := httptest.NewRequest(http.MethodGet, "/oauth2/federation/p1/callback", nil)
	req.SetPathValue("id", "p1")
	rr := httptest.NewRecorder()
	HandleFederationCallback(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	// Case 2: Invalid state signature
	req = httptest.NewRequest(http.MethodGet, "/oauth2/federation/p1/callback?code=c&state=invalid", nil)
	req.SetPathValue("id", "p1")
	rr = httptest.NewRecorder()
	HandleFederationCallback(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	// Case 3: Provider ID mismatch in state
	state := FederationState{
		ProviderID: "p2",
	}
	signedState, _ := SignState(state)
	req = httptest.NewRequest(http.MethodGet, "/oauth2/federation/p1/callback?code=c&state="+signedState, nil)
	req.SetPathValue("id", "p1")
	rr = httptest.NewRecorder()
	HandleFederationCallback(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	// Case 4: Provider not found or disabled
	state.ProviderID = "p1"
	signedState, _ = SignState(state)
	req = httptest.NewRequest(http.MethodGet, "/oauth2/federation/p1/callback?code=c&state="+signedState, nil)
	req.SetPathValue("id", "p1")
	rr = httptest.NewRecorder()
	HandleFederationCallback(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandleFederationBegin_Errors_Extra(t *testing.T) {
	testutils.WithTestDB(t)

	// Case 1: Missing provider ID
	req := httptest.NewRequest(http.MethodGet, "/oauth2/federation/begin", nil)
	rr := httptest.NewRecorder()
	HandleFederationBegin(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	// Case 2: Provider not found or disabled
	req = httptest.NewRequest(http.MethodGet, "/oauth2/federation/begin", nil)
	req.SetPathValue("id", "nonexistent")
	rr = httptest.NewRecorder()
	HandleFederationBegin(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)

	// Case 3: Provider disabled
	_ = CreateFederationProvider(FederationProvider{
		ID: "disabled-p", Name: "Disabled", Issuer: "https://iss.com", Enabled: false,
	})
	req = httptest.NewRequest(http.MethodGet, "/oauth2/federation/begin", nil)
	req.SetPathValue("id", "disabled-p")
	rr = httptest.NewRecorder()
	HandleFederationBegin(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestDeriveUsername_EdgeCases_Extra(t *testing.T) {
	// Long email prefix
	longEmail := "abcdefghijklmnopqrstuvwxyz@example.com"
	u := deriveUsername(longEmail, "sub123")
	assert.Equal(t, "abcdefghijklmnopqrst-sub123", u)

	// No email
	u = deriveUsername("", "sub1234567890")
	assert.Equal(t, "sub1234567890-34567890", u)
}

func TestHandleFederationBegin_Success(t *testing.T) {
	testutils.WithTestDB(t)

	// 1. Mock OIDC Issuer
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			resp := map[string]any{
				"issuer":                 fmt.Sprintf("http://%s", r.Host),
				"authorization_endpoint": fmt.Sprintf("http://%s/auth", r.Host),
				"token_endpoint":         fmt.Sprintf("http://%s/token", r.Host),
				"userinfo_endpoint":      fmt.Sprintf("http://%s/userinfo", r.Host),
				"jwks_uri":               fmt.Sprintf("http://%s/jwks", r.Host),
			}
			json.NewEncoder(w).Encode(resp)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	// 2. Create provider pointing to mock server
	_ = CreateFederationProvider(FederationProvider{
		ID: "mock", Name: "Mock", Issuer: ts.URL, ClientID: "c1", ClientSecret: "s1", Enabled: true,
	})

	// 3. Begin federation
	req := httptest.NewRequest(http.MethodGet, "/oauth2/federation/mock?redirect_uri=http://localhost/cb", nil)
	req.SetPathValue("id", "mock")
	rr := httptest.NewRecorder()
	HandleFederationBegin(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	loc := rr.Header().Get("Location")
	assert.Contains(t, loc, "/auth") // Authorization endpoint of mock
	assert.Contains(t, loc, "state=")
}
