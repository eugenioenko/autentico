package security

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/user"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/stretchr/testify/require"
)

// A software authenticator exercises the real WebAuthn verifier, not a mocked
// FinishRegistration call. None attestation is the default RP attestation policy.
type signupAuthenticator struct {
	key *ecdsa.PrivateKey
	id  []byte
}

func newSignupAuthenticator(t *testing.T) *signupAuthenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	id := make([]byte, 32)
	_, err = rand.Read(id)
	require.NoError(t, err)
	return &signupAuthenticator{key: key, id: id}
}

func (a *signupAuthenticator) response(t *testing.T, origin, challenge, userID string, registration bool) []byte {
	t.Helper()
	u, err := url.Parse(origin)
	require.NoError(t, err)
	rpHash := sha256.Sum256([]byte(u.Hostname()))
	authData := append([]byte{}, rpHash[:]...)
	kind := "webauthn.get"
	if registration {
		kind = "webauthn.create"
		authData = append(authData, 0x45, 0, 0, 0, 0)    // UP, UV, attested credential; counter zero
		authData = append(authData, make([]byte, 16)...) // AAGUID
		authData = binary.BigEndian.AppendUint16(authData, uint16(len(a.id)))
		authData = append(authData, a.id...)
		cose, err := webauthncbor.Marshal(map[int]any{
			1: 2, 3: -7, -1: 1, -2: a.key.X.FillBytes(make([]byte, 32)), -3: a.key.Y.FillBytes(make([]byte, 32)),
		})
		require.NoError(t, err)
		authData = append(authData, cose...)
	} else {
		authData = append(authData, 0x05, 0, 0, 0, 1) // UP, UV; counter one
	}
	clientData, err := json.Marshal(map[string]any{"type": kind, "challenge": challenge, "origin": origin, "crossOrigin": false})
	require.NoError(t, err)
	encode := base64.RawURLEncoding.EncodeToString
	response := map[string]any{"clientDataJSON": encode(clientData)}
	if registration {
		attestation, err := webauthncbor.Marshal(map[string]any{"fmt": "none", "authData": authData, "attStmt": map[string]any{}})
		require.NoError(t, err)
		response["attestationObject"] = encode(attestation)
		response["transports"] = []string{"internal"}
	} else {
		clientHash := sha256.Sum256(clientData)
		signed := sha256.Sum256(append(authData, clientHash[:]...))
		signature, err := ecdsa.SignASN1(rand.Reader, a.key, signed[:])
		require.NoError(t, err)
		response["authenticatorData"], response["signature"], response["userHandle"] = encode(authData), encode(signature), encode([]byte(userID))
	}
	body, err := json.Marshal(map[string]any{"id": encode(a.id), "rawId": encode(a.id), "type": "public-key", "response": response})
	require.NoError(t, err)
	return body
}

func beginSignupCeremony(t *testing.T, ts *TestServer, path string, p url.Values) (string, string) {
	t.Helper()
	resp, err := ts.Client.Get(ts.BaseURL + path + "?" + p.Encode())
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	var options struct {
		ChallengeID string `json:"challenge_id"`
		Options     struct {
			PublicKey struct {
				Challenge string `json:"challenge"`
			} `json:"publicKey"`
		} `json:"options"`
	}
	require.NoError(t, json.Unmarshal(body, &options))
	require.NotEmpty(t, options.Options.PublicKey.Challenge)
	return options.ChallengeID, options.Options.PublicKey.Challenge
}

func finishSignupCeremony(t *testing.T, ts *TestServer, path, id string, body []byte) string {
	t.Helper()
	resp, err := ts.Client.Post(ts.BaseURL+path+"?challenge_id="+id, "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(data))
	var result struct {
		Redirect string `json:"redirect"`
	}
	require.NoError(t, json.Unmarshal(data, &result))
	require.NotEmpty(t, result.Redirect)
	return result.Redirect
}

func TestPasskeySignup_EnforcesPolicyOverHTTP(t *testing.T) {
	for _, tc := range []struct {
		name, mode, override string
		allow                bool
		want                 int
	}{
		{"signup disabled", "password_and_passkey", "", false, 403},
		{"password only", "password", "", true, 403},
		{"client disabled", "passkey_only", "0", true, 403},
		{"client enabled", "passkey_only", "1", false, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := startTestServer(t)
			testutils.WithConfigOverride(t, func() {
				config.Values.AuthAllowSelfSignup, config.Values.AuthMode = tc.allow, tc.mode
				config.Bootstrap.AppDomain = "127.0.0.1"
			})
			if tc.override != "" {
				_, err := db.GetDB().Exec("UPDATE clients SET allow_self_signup=? WHERE client_id='test-client'", tc.override)
				require.NoError(t, err)
			}
			p := browserAuthorization(t, ts)
			p.Set("username", "policy-signup")
			resp, err := ts.Client.Get(ts.BaseURL + "/oauth2/passkey/register/begin?" + p.Encode())
			require.NoError(t, err)
			_ = resp.Body.Close()
			require.Equal(t, tc.want, resp.StatusCode)
			var n int
			require.NoError(t, db.GetDB().QueryRow("SELECT COUNT(*) FROM users").Scan(&n))
			if tc.want != 200 {
				require.Zero(t, n)
			} else {
				require.Equal(t, 1, n)
			}
		})
	}
}

func TestPasskeySignup_RealCeremonyAndEmailVerification(t *testing.T) {
	for _, verify := range []bool{false, true} {
		name := "without verification"
		if verify {
			name = "with required verification"
		}
		t.Run(name, func(t *testing.T) {
			ts := startTestServer(t)
			testutils.WithConfigOverride(t, func() {
				config.Values.AuthAllowSelfSignup = true
				config.Values.AuthMode = "passkey_only"
				config.Values.RequireEmailVerification = verify
				config.Bootstrap.AppDomain = "127.0.0.1"
			})
			var messages <-chan string
			if verify {
				messages = captureVerificationEmail(t)
			}
			p := browserAuthorization(t, ts)
			p.Set("username", "real-passkey-user")
			p.Set("email", "real-passkey@example.com")
			id, challenge := beginSignupCeremony(t, ts, "/oauth2/passkey/register/begin", p)
			usr, err := user.UserByUsername(p.Get("username"))
			require.NoError(t, err)
			authenticator := newSignupAuthenticator(t)
			body := authenticator.response(t, ts.BaseURL, challenge, usr.ID, true)
			// Even a valid ceremony response cannot be submitted by a different browser.
			jar, err := cookiejar.New(nil)
			require.NoError(t, err)
			stranger := &http.Client{Jar: jar}
			resp, err := stranger.Post(ts.BaseURL+"/oauth2/passkey/register/finish?challenge_id="+id, "application/json", bytes.NewReader(body))
			require.NoError(t, err)
			_ = resp.Body.Close()
			require.Equal(t, 403, resp.StatusCode)
			redirect := finishSignupCeremony(t, ts, "/oauth2/passkey/register/finish", id, body)
			if verify {
				require.Contains(t, redirect, "/verify-email/pending?")
				require.NotContains(t, redirect, "token=")
				// A new credential must not enable bypassing verification via either login route.
				for _, mode := range []string{"login", "discoverable"} {
					id, challenge = beginSignupCeremony(t, ts, "/oauth2/passkey/"+mode+"/begin", p)
					loginRedirect := finishSignupCeremony(t, ts, "/oauth2/passkey/"+mode+"/finish", id, authenticator.response(t, ts.BaseURL, challenge, usr.ID, false))
					require.Contains(t, loginRedirect, "/verify-email/pending?")
				}
				for _, table := range []string{"auth_codes", "idp_sessions", "sessions"} {
					var n int
					require.NoError(t, db.GetDB().QueryRow("SELECT COUNT(*) FROM "+table).Scan(&n))
					require.Zero(t, n, table)
				}
				resp, err = ts.Client.Get(redirect)
				require.NoError(t, err)
				page, err := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				require.NoError(t, err)
				require.Equal(t, 200, resp.StatusCode)
				require.Contains(t, string(page), "resend-verification")
				var message string
				select {
				case message = <-messages:
				case <-time.After(2 * time.Second):
					t.Fatal("verification email not delivered")
				}
				match := regexp.MustCompile(`href="([^"]*/verify-email\?[^"]*)"`).FindStringSubmatch(message)
				require.Len(t, match, 2, message)
				resp, err = ts.Client.Get(html.UnescapeString(match[1]))
				require.NoError(t, err)
				_ = resp.Body.Close()
				require.Equal(t, 302, resp.StatusCode)
				redirect = resp.Header.Get("Location")
				usr, err = user.UserByID(usr.ID)
				require.NoError(t, err)
				require.True(t, usr.IsEmailVerified)
			}
			callback, err := url.Parse(redirect)
			require.NoError(t, err)
			require.Equal(t, "localhost:3000", callback.Host)
			require.NotEmpty(t, callback.Query().Get("code"))
			tokens := exchangeCode(t, ts, callback.Query().Get("code"), p.Get("redirect_uri"), "test-client", testCodeVerifier)
			require.NotEmpty(t, tokens.AccessToken)
			userinfo, err := http.NewRequest("GET", ts.BaseURL+"/oauth2/userinfo", nil)
			require.NoError(t, err)
			userinfo.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
			resp, err = ts.Client.Do(userinfo)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()
			var profile map[string]any
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&profile))
			require.Equal(t, "real-passkey@example.com", profile["email"])
			require.False(t, strings.Contains(redirect, "/pending"))
		})
	}
}

func TestPasskeySignup_EmailDeliveryFailureDoesNotAuthenticate(t *testing.T) {
	ts := startTestServer(t)
	// Bind then close a local port, giving a deterministic connection refusal.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	host, port, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)
	require.NoError(t, listener.Close())
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthAllowSelfSignup = true
		config.Values.AuthMode = "passkey_only"
		config.Values.RequireEmailVerification = true
		config.Values.SmtpHost, config.Values.SmtpPort = host, port
		config.Values.SmtpUsername, config.Values.SmtpPassword = "", ""
		config.Bootstrap.AppDomain = "127.0.0.1"
	})
	p := browserAuthorization(t, ts)
	p.Set("username", "delivery-failed")
	p.Set("email", "delivery@example.com")
	id, challenge := beginSignupCeremony(t, ts, "/oauth2/passkey/register/begin", p)
	usr, err := user.UserByUsername(p.Get("username"))
	require.NoError(t, err)
	authenticator := newSignupAuthenticator(t)
	resp, err := ts.Client.Post(ts.BaseURL+"/oauth2/passkey/register/finish?challenge_id="+id, "application/json", bytes.NewReader(authenticator.response(t, ts.BaseURL, challenge, usr.ID, true)))
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, 503, resp.StatusCode)
	for _, table := range []string{"auth_codes", "idp_sessions", "sessions"} {
		var n int
		require.NoError(t, db.GetDB().QueryRow("SELECT COUNT(*) FROM "+table).Scan(&n))
		require.Zero(t, n, table)
	}
	// The valid passkey remains usable to reach the resend page after SMTP recovers.
	id, challenge = beginSignupCeremony(t, ts, "/oauth2/passkey/login/begin", p)
	redirect := finishSignupCeremony(t, ts, "/oauth2/passkey/login/finish", id, authenticator.response(t, ts.BaseURL, challenge, usr.ID, false))
	require.Contains(t, redirect, "/verify-email/pending?")
}

func TestPasskeyLogin_RechecksAuthenticationMode(t *testing.T) {
	for _, mode := range []string{"login", "discoverable"} {
		t.Run(mode, func(t *testing.T) {
			ts := startTestServer(t)
			testutils.WithConfigOverride(t, func() {
				config.Values.AuthAllowSelfSignup = true
				config.Values.AuthMode = "passkey_only"
				config.Bootstrap.AppDomain = "127.0.0.1"
			})
			p := browserAuthorization(t, ts)
			p.Set("username", "mode-change-user")
			id, challenge := beginSignupCeremony(t, ts, "/oauth2/passkey/register/begin", p)
			usr, err := user.UserByUsername(p.Get("username"))
			require.NoError(t, err)
			authenticator := newSignupAuthenticator(t)
			finishSignupCeremony(t, ts, "/oauth2/passkey/register/finish", id, authenticator.response(t, ts.BaseURL, challenge, usr.ID, true))
			// Closing signup must leave existing-user login available.
			config.Values.AuthAllowSelfSignup = false
			id, challenge = beginSignupCeremony(t, ts, "/oauth2/passkey/"+mode+"/begin", p)
			body := authenticator.response(t, ts.BaseURL, challenge, usr.ID, false)
			config.Values.AuthMode = "password"
			resp, err := ts.Client.Post(ts.BaseURL+"/oauth2/passkey/"+mode+"/finish?challenge_id="+id, "application/json", bytes.NewReader(body))
			require.NoError(t, err)
			_ = resp.Body.Close()
			require.Equal(t, 403, resp.StatusCode)
			var used bool
			require.NoError(t, db.GetDB().QueryRow("SELECT used FROM passkey_challenges WHERE id=?", id).Scan(&used))
			require.False(t, used)
			var lastUsed *time.Time
			require.NoError(t, db.GetDB().QueryRow("SELECT last_used_at FROM passkey_credentials WHERE user_id=?", usr.ID).Scan(&lastUsed))
			require.Nil(t, lastUsed, "rejection must precede credential mutation")
			for _, table := range []string{"auth_codes", "idp_sessions"} {
				var n int
				require.NoError(t, db.GetDB().QueryRow("SELECT COUNT(*) FROM "+table).Scan(&n))
				require.Equal(t, 1, n, "only the initial signup may issue authorization state")
			}
			resp, err = ts.Client.Get(ts.BaseURL + "/oauth2/passkey/" + mode + "/begin?" + p.Encode())
			require.NoError(t, err)
			_ = resp.Body.Close()
			require.Equal(t, 403, resp.StatusCode)
			// Restoring passkeys permits the still-unused assertion, with signup closed.
			config.Values.AuthMode = "password_and_passkey"
			redirect := finishSignupCeremony(t, ts, "/oauth2/passkey/"+mode+"/finish", id, body)
			require.Contains(t, redirect, "code=")
		})
	}
}
